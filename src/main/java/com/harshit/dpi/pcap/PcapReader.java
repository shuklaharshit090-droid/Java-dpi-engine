package com.harshit.dpi.pcap;

import java.io.*;
import java.nio.*;
import java.nio.file.*;

public final class PcapReader implements AutoCloseable {
    private final DataInputStream in;
    private final ByteOrder order;
    private final byte[] globalHeader;

    public PcapReader(Path path) throws IOException {
        in = new DataInputStream(new BufferedInputStream(Files.newInputStream(path), 1 << 16));
        globalHeader = in.readNBytes(24);
        if (globalHeader.length < 24) throw new IOException("Not a valid pcap file");

        int magic = ByteBuffer.wrap(globalHeader).order(ByteOrder.BIG_ENDIAN).getInt(0);
        if (magic == 0xa1b2c3d4) order = ByteOrder.BIG_ENDIAN;
        else if (magic == 0xd4c3b2a1) order = ByteOrder.LITTLE_ENDIAN;
        else throw new IOException("Unsupported pcap magic: 0x" + Integer.toHexString(magic)
                    + " (is this a .pcapng file?)");

        int linkType = ByteBuffer.wrap(globalHeader).order(order).getInt(20);
        if (linkType != 1) throw new IOException("Only Ethernet (linktype 1) supported, got " + linkType);
    }

    /** Returns the next packet, or null at end of file. */
    public RawPacket next() throws IOException {
        byte[] h = in.readNBytes(16);
        if (h.length == 0) return null;
        if (h.length < 16) throw new EOFException("Truncated packet header");

        ByteBuffer hb = ByteBuffer.wrap(h).order(order);
        long sec  = hb.getInt(0) & 0xFFFFFFFFL;
        long usec = hb.getInt(4) & 0xFFFFFFFFL;
        int incl  = hb.getInt(8);
        int orig  = hb.getInt(12);
        if (incl < 0 || incl > 262_144) throw new IOException("Corrupt packet length: " + incl);

        byte[] data = in.readNBytes(incl);
        if (data.length < incl) throw new EOFException("Truncated packet body");
        return new RawPacket(sec, usec, orig, data);
    }

    public byte[] globalHeader() { return globalHeader.clone(); }

    @Override public void close() throws IOException { in.close(); }
}