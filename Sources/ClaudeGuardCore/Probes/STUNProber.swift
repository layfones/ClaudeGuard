import Foundation
import Network
import Darwin

/// 纯 Swift 基于 `NWConnection` UDP 的 RFC 5389 STUN 公网出口探测器（支持 IPv4 与 IPv6）。
public struct STUNProber: Sendable {
    public struct Server: Sendable, Equatable {
        public let host: String
        public let port: UInt16

        public init(host: String, port: UInt16) {
            self.host = host
            self.port = port
        }
    }

    public struct Result: Sendable, Equatable {
        public var ip: String?
        public var latencyMs: Int?
        public var errorDescription: String?

        public init(ip: String? = nil, latencyMs: Int? = nil, errorDescription: String? = nil) {
            self.ip = ip
            self.latencyMs = latencyMs
            self.errorDescription = errorDescription
        }
    }

    public static let defaultServers: [Server] = [
        Server(host: "stun.cloudflare.com", port: 3478),
        Server(host: "stun.l.google.com", port: 19302),
        Server(host: "stun1.l.google.com", port: 19302)
    ]

    public static let magicCookie: [UInt8] = [0x21, 0x12, 0xA4, 0x42]

    public init() {}

    /// 构造 RFC 5389 20 字节 STUN Binding Request 报文。
    public static func buildBindingRequest(transactionID: [UInt8]? = nil) -> (packet: Data, txID: [UInt8]) {
        let tx: [UInt8]
        if let provided = transactionID, provided.count == 12 {
            tx = provided
        } else {
            tx = (0..<12).map { _ in UInt8.random(in: 0...255) }
        }
        var bytes: [UInt8] = [0x00, 0x01, 0x00, 0x00] // Binding Request, length 0
        bytes.append(contentsOf: magicCookie)
        bytes.append(contentsOf: tx)
        return (Data(bytes), tx)
    }

    /// 解析 RFC 5389 STUN Binding Success Response（支持 XOR-MAPPED-ADDRESS 0x0020 与 MAPPED-ADDRESS 0x0001）。
    public static func parseBindingResponse(
        _ bytes: [UInt8],
        expectedTransactionID: [UInt8]? = nil
    ) -> String? {
        guard bytes.count >= 20,
              bytes[0] == 0x01,
              bytes[1] == 0x01 else {
            return nil
        }

        let msgLen = (Int(bytes[2]) << 8) | Int(bytes[3])
        let txID = Array(bytes[8..<20])
        if let expected = expectedTransactionID, expected.count == 12, txID != expected {
            return nil
        }

        let end = min(20 + msgLen, bytes.count)
        var offset = 20

        while offset + 4 <= end {
            let attrType = (Int(bytes[offset]) << 8) | Int(bytes[offset + 1])
            let attrLen = (Int(bytes[offset + 2]) << 8) | Int(bytes[offset + 3])
            let valueStart = offset + 4
            guard valueStart + attrLen <= bytes.count else { break }

            if attrType == 0x0020 || attrType == 0x0001 {
                if attrLen >= 8 {
                    let family = bytes[valueStart + 1]
                    if family == 0x01 {
                        // IPv4 (4 bytes)
                        var raw = Array(bytes[(valueStart + 4)..<(valueStart + 8)])
                        if attrType == 0x0020 {
                            for k in 0..<4 { raw[k] ^= magicCookie[k] }
                        }
                        let ip = "\(raw[0]).\(raw[1]).\(raw[2]).\(raw[3])"
                        if CIDRMatcher.isValidLiteralIP(ip) {
                            return ip
                        }
                    } else if family == 0x02 && attrLen >= 20 {
                        // IPv6 (16 bytes): XOR with magicCookie (4B) + txID (12B)
                        var raw = Array(bytes[(valueStart + 4)..<(valueStart + 20)])
                        if attrType == 0x0020 {
                            let xorKey = magicCookie + txID
                            for k in 0..<16 { raw[k] ^= xorKey[k] }
                        }
                        var addr = in6_addr()
                        withUnsafeMutableBytes(of: &addr) { dst in
                            dst.copyBytes(from: raw)
                        }
                        var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                        let formatted: String? = buf.withUnsafeMutableBufferPointer { ptr in
                            guard let base = ptr.baseAddress else { return nil }
                            guard inet_ntop(AF_INET6, &addr, base, socklen_t(INET6_ADDRSTRLEN)) != nil else {
                                return nil
                            }
                            return String(cString: base)
                        }
                        if let ip = formatted, CIDRMatcher.isValidLiteralIP(ip) {
                            return ip
                        }
                    }
                }
            }

            offset = valueStart + attrLen
            if attrLen % 4 != 0 {
                offset += 4 - (attrLen % 4)
            }
        }
        return nil
    }

    public func probe(
        timeout: TimeInterval = 1.5,
        servers: [Server] = STUNProber.defaultServers
    ) async -> Result {
        let started = Date()
        return await withTaskGroup(of: (String, Int)?.self) { group in
            for server in servers {
                group.addTask {
                    await Self.querySingleServer(server, timeout: timeout)
                }
            }

            while let next = await group.next() {
                if let hit = next {
                    group.cancelAll()
                    return Result(ip: hit.0, latencyMs: hit.1)
                }
            }

            let elapsed = Int(Date().timeIntervalSince(started) * 1000)
            return Result(
                ip: nil,
                latencyMs: elapsed,
                errorDescription: "UDP STUN 探测未返回（可能被网络阻断或离线）"
            )
        }
    }

    private static func querySingleServer(
        _ server: Server,
        timeout: TimeInterval
    ) async -> (String, Int)? {
        guard let nwPort = NWEndpoint.Port(rawValue: server.port) else { return nil }
        let (packet, txID) = buildBindingRequest()
        let started = Date()

        return await withCheckedContinuation { continuation in
            let box = OnceContinuationBox<(String, Int)?>(continuation)
            let conn = NWConnection(host: NWEndpoint.Host(server.host), port: nwPort, using: .udp)
            let queue = DispatchQueue(label: "com.claudeguard.stun.\(server.host)")

            queue.asyncAfter(deadline: .now() + timeout) {
                conn.cancel()
                box.resume(returning: nil)
            }

            conn.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    conn.send(content: packet, completion: .contentProcessed { sendErr in
                        if sendErr != nil {
                            conn.cancel()
                            box.resume(returning: nil)
                        }
                    })
                    conn.receiveMessage { data, _, _, recvErr in
                        conn.cancel()
                        guard recvErr == nil,
                              let data = data,
                              let ip = parseBindingResponse(Array(data), expectedTransactionID: txID) else {
                            box.resume(returning: nil)
                            return
                        }
                        let ms = Int(Date().timeIntervalSince(started) * 1000)
                        box.resume(returning: (ip, ms))
                    }
                case .failed, .cancelled:
                    box.resume(returning: nil)
                default:
                    break
                }
            }
            conn.start(queue: queue)
        }
    }
}
