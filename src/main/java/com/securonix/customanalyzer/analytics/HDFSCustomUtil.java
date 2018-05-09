/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.securonix.customanalyzer.analytics;

import com.securonix.hdfs.client.HDFSClient;
import com.securonix.snyper.common.EnrichedEventObject;
import com.securonix.snyper.common.JSONUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FileSystem;

/**
 * HDFSCustomUtil
 * @author manishkumar
 */
public class HDFSCustomUtil {

    private final static Logger LOGGER = LogManager.getLogger();
    private static final SimpleDateFormat DAY_FORMAT = new SimpleDateFormat("yyyyMMdd");
    
    /**
     * Write sample EEO events into HDFS
     *
     * @param customEventsFolder : HDFS directory location to store sample data. 
     * @param hc : hdfsClient instance
     * @param customEvents : List of EnrichedEventObjects
     * @throws java.io.IOException
     */

    public static void writetoHDFS(String customEventsFolder, final HDFSClient hc, final List<EnrichedEventObject> customEvents) throws IOException {

        final String folder = customEventsFolder + "/" + DAY_FORMAT.format(new Date());
        LOGGER.info("Sample custom folder for the day- {}", folder);
        hc.createDirectoryIfNotExists(folder);

        final String json = JSONUtil.toJSON(customEvents);
        FileSystem fs = hc.getFs();

        String file = folder + "/_customevents.json";

        OutputStream os = null;

        if (fs.exists(hc.getPath(file))) {
            os = fs.append(hc.getPath(file));
        } else {
            os = fs.create(hc.getPath(file), (short) 1);
        }

        try {
            OutputStreamWriter osw = new OutputStreamWriter(os, "UTF-8");
            BufferedWriter br = new BufferedWriter(osw);
            {
                br.write(json);
                br.newLine();
                br.flush();
                LOGGER.debug("Custom events written to HDFS, size :" + customEvents.size());
            }
        } catch (IOException ex) {
            LOGGER.error("Error writing custom events to HDFS- {}", file, ex);
        } finally {
            os.close();
        }

    }
    
    /**
     * Read sample data from HDFS
     *
     * @param customEventsPath : HDFS directory location to read JSON data     
     * @param hdfsClient : hdfsClient instance   
     * @return List of EEO events      
     */

    public static List<EnrichedEventObject> readFromHDFS(String customEventsPath, HDFSClient hdfsClient) {

        List<EnrichedEventObject> finalEEOList = new ArrayList<>();
        List<String> fileNames = hdfsClient.getFileList(customEventsPath);
        for (String file : fileNames) {
            List<String> dates = hdfsClient.getFileList(file);

            for (String date : dates) {

                FSDataInputStream fdi = hdfsClient.getInputStream(date);
                BufferedReader br = new BufferedReader(new InputStreamReader(fdi));
                String line = "";
                try {
                    line = br.readLine();
                    fdi.close();

                    List<EnrichedEventObject> eeos = JSONUtil.fromJSON(line);
                    finalEEOList.addAll(eeos);

                } catch (Exception ex) {
                    LOGGER.error("Error reading custom events to HDFS- {}", ex);
                }

            }
        }

        return finalEEOList;
    }

    /**
     * Create sample List of EEO objects
     *
     * @return : List of EEO objects      
     */
    
    public static List<EnrichedEventObject> getSampleEEO() {
        List<EnrichedEventObject> eeoList = new ArrayList<>();

        for (int i = 1; i < 11; i++) {
            EnrichedEventObject eeo = new EnrichedEventObject();
            eeo.setOldfiletype("oldfiletype");
            eeo.setRg_vendor("TestVendor");
            eeo.setTransactionstring1("Login Failure");
            eeo.setAccountname("AAAA");
            eeo.setRg_id(50l);
            eeo.setEventid("dhhssjbnh");
            eeo.setEventtime(System.currentTimeMillis());
            eeo.setJobid(-1l);
            eeo.setJobstarttime(System.currentTimeMillis());
            eeo.setRg_name("CustomResourceGroup");
            eeo.setResourcename("CustomResource");
            eeo.setResourcetype("Test Resource");
            eeo.setTenantid(10l);
            eeo.setTenantname("Securonix");
            eeo.setMessage("Custom Message");
            eeoList.add(eeo);
        }

        return eeoList;
    }
}
