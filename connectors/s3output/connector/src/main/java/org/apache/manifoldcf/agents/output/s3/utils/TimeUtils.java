package org.apache.manifoldcf.agents.output.s3.utils;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Date;

/**
 * Created by jeckep on 08.09.17.
 */
public class TimeUtils {
    public static String toISOformatAtUTC(Date date){
        return date.toInstant().atZone(ZoneId.of("UTC")).format(DateTimeFormatter.ISO_INSTANT);
    }

    public static String yyyyMMddHHmmUTCnow(){
        return Instant.now().atZone(ZoneId.of("UTC")).format(DateTimeFormatter.ofPattern("yyyyMMddHHmm"));
    }
}
