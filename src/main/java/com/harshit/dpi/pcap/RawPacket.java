package com.harshit.dpi.pcap;

public record RawPacket(long tsSec, long tsUsec, int origLen, byte[] data) {}