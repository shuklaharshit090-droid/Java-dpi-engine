package com.harshit.dpi.cli;

import com.harshit.dpi.pcap.PcapReader;
import com.harshit.dpi.pcap.RawPacket;
import java.nio.file.Path;

public class Main {
    public static void main(String[] args) throws Exception {
        Path file = Path.of(args.length > 0 ? args[0] : "samples/test_dpi.pcap");
        int count = 0;
        long bytes = 0;
        try (PcapReader reader = new PcapReader(file)) {
            RawPacket p;
            while ((p = reader.next()) != null) {
                count++;
                bytes += p.data().length;
            }
        }
        System.out.printf("Packets: %d, Bytes: %d%n", count, bytes);
    }
}