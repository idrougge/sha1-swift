// SHA-1 implementation in Swift
// $AUTHOR: Iggy Drougge
// $VER: 1.0

import Foundation

infix operator <<< {associativity none precedence 160}  // Left rotation (or cyclic shift) operator
private func <<< (lhs:uint32, rhs:uint32) -> uint32 {
    return lhs << rhs | lhs >> (32-rhs)
}
public struct SHA1 {
    private static let CHUNKSIZE=80
    // Initialise variables:
    private static var h0:uint32 = 0x67452301
    private static var h1:uint32 = 0xEFCDAB89
    private static var h2:uint32 = 0x98BADCFE
    private static var h3:uint32 = 0x10325476
    private static var h4:uint32 = 0xC3D2E1F0
    
    private struct context {
        var h0=SHA1.h0
        var h1=SHA1.h1
        var h2=SHA1.h2
        var h3=SHA1.h3
        var h4=SHA1.h4
        var h:[uint32]=[SHA1.h0,SHA1.h1,SHA1.h2,SHA1.h3,SHA1.h4]
        
        private mutating func processChunk(inout chunk:[uint32]) {
            chunk=chunk.map{$0.bigEndian}   // The numbers must be big-endian
            for i in 16...79 {              // Extend the chunk to 80 longwords
                chunk[i] = (chunk[i-3] ^ chunk[i-8] ^ chunk[i-14] ^ chunk[i-16]) <<< 1
                //print("w[\(i)]=\(String(format:"%08X,chunk[i]))")
            }
            // Print out chunk values
            /*
             for (key, value) in chunk[0...15].enumerate() {
             print(String(format:"%d: %08X", key, value), terminator:" ")
             }
             print()
             */
            // Initialise hash value for this chunk:
            var a,b,c,d,e,f,k,temp:uint32
            a=h[0]; b=h[1]; c=h[2]; d=h[3]; e=h[4]
            f=0x0; k=0x0
            // Main loop
            for i in 0...79 {
                switch i {
                case 0...19:
                    f = (b & c) | ((~b) & d)
                    k = 0x5A827999
                case 20...39:
                    f = b ^ c ^ d
                    k = 0x6ED9EBA1
                case 40...59:
                    f = (b & c) | (b & d) | (c & d)
                    k = 0x8F1BBCDC
                case 60...79:
                    f = b ^ c ^ d
                    k = 0xCA62C1D6
                default: break
                }
                temp = a <<< 5 &+ f &+ e &+ k &+ chunk[i]
                e = d
                d = c
                c = b <<< 30
                b = a
                a = temp
                //print(String(format: "t=%d %08X %08X %08X %08X %08X", i, a, b, c, d, e))
            }
            //Add this chunk's hash to result so far:
            h[0] = h[0] &+ a
            h[1] = h[1] &+ b
            h[2] = h[2] &+ c
            h[3] = h[3] &+ d
            h[4] = h[4] &+ e
        }
    }
    
    private static func processData(data:NSData) -> SHA1.context? {
        var context=SHA1.context()
        var w=[uint32](count: CHUNKSIZE, repeatedValue: 0x00000000)
        let ml=data.length << 3   // Message length in bits
        data.getBytes(&w, length: 64)
        var range=NSMakeRange(0, 64)
        while data.length > NSMaxRange(range) {
            print("Reading \(range.length) bytes @ position \(range.location)")
            data.getBytes(&w, range: range)
            context.processChunk(&w)
            range=NSMakeRange(NSMaxRange(range), 64)
        }
        w=[uint32](count: CHUNKSIZE, repeatedValue: 0x00000000)
        range=NSMakeRange(range.location, data.length-range.location)
        data.getBytes(&w, range: range)
        let bytetochange=range.length % 4
        let shift = uint32(bytetochange * 8)
        w[range.length/4] |= 0x80 << shift
        
        if range.length+1 > 56 {
            context.processChunk(&w)
            w=[uint32](count: CHUNKSIZE, repeatedValue: 0x00000000)
        }
        w[15] = uint32(ml).bigEndian
        context.processChunk(&w)
        return context
    }
    private static func hexString(context:SHA1.context?) -> String? {
        guard let c=context else {return nil}
        var hh:String=""
        c.h.map{hh+=String(format:"%8X\($0.distanceTo(c.h.last!)==0 ? "":" ")",$0)}
        return hh
        //return String(format: "%8X %8X %8X %8X %8X", c.h0, c.h1, c.h2, c.h3, c.h4)
    }
    private static func dataFromFile(filename:String) -> SHA1.context? {
        guard let file=NSData(contentsOfFile:filename) else {return nil}
        return processData(file)
    }
    
    static public func hexStringFromFile(filename:String) -> String? {
        return hexString(SHA1.dataFromFile(filename))
    }
    
    public static func hashFromFile(filename:String) -> [Int]? {
        return dataFromFile(filename)?.h.map{Int($0)}
    }
    
    public static func hexStringFromData(data:NSData) -> String? {
        return hexString(SHA1.processData(data))
    }
    
    public static func hashFromData(data:NSData) -> [Int]? {
        return processData(data)?.h.map{Int($0)}
    }
    
    public static func hexStringFromString(str:String) -> String? {
        return hexString(SHA1.processData(str.dataUsingEncoding(NSUTF8StringEncoding)!))
    }
    
    public static func hashFromString(str:String) -> [Int]? {
        return processData(str.dataUsingEncoding(NSUTF8StringEncoding)!)?.h.map{Int($0)}
    }
    
}
