package com.harshit.dpi.pcap;

import org.junit.jupiter.api.Test;
import java.nio.file.Path;
import static org.junit.jupiter.api.Assertions.*;

class PcapReaderTest {

    @Test
    void readsAllPacketsFromSampleCapture() throws Exception {
        int count = 0;
        long bytes = 0;
        try (PcapReader r = new PcapReader(Path.of("samples/test_dpi.pcap"))) {
            RawPacket p;
            while ((p = r.next()) != null) {
                count++;
                bytes += p.data().length;
            }
        }
        assertEquals(77, count);
        assertEquals(5738, bytes);
    }

    @Test
    void rejectsNonPcapFile() {
        assertThrows(java.io.IOException.class,
                () -> new PcapReader(Path.of("pom.xml")));
    }
}