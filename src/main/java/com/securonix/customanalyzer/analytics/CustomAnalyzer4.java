/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.securonix.customanalyzer.analytics;

import com.securonix.customanalyzer.hbaseutil.dao.EmailRecipientCountDAO;
import com.securonix.hbasecorrelator.dao.CorrelationRulesHDAO;
import com.securonix.hbaseutil.HBaseClient;
import com.securonix.hbaseutil.HBaseConstants;
import static com.securonix.hbaseutil.HBaseConstants.TABLE_CORRELATION_RULES_H;
import static com.securonix.hbaseutil.HBaseConstants.TABLE_VIOLATIONS;
import com.securonix.hbaseutil.dao.AbstractTableDAO;
import com.securonix.hbaseutil.dao.KafkaOffsetDAO;
import com.securonix.hbaseutil.dao.SnyperErrorDAO;
import com.securonix.hbaseutil.dao.ViolationDAO;
import com.securonix.snyper.common.MiniEEO;
import com.securonix.snyper.config.beans.HBaseConfigBean;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import com.securonix.customanalyzer.hbaseutil.beans.EmailRecipientCount;
import org.apache.hadoop.hbase.filter.Filter;

/**
 *
 * @author manishkumar
 */
public class CustomAnalyzer4 {

    private final Logger LOGGER = LogManager.getLogger();

    HBaseClient hbaseClient = null;

    EmailRecipientCountDAO eCountDAO;

    /**
     * Hbase Client gets initialized.
     *
     * @param hbaseConfigBean Hbase Configuration Bean
     */
    public void init(final HBaseConfigBean hbaseConfigBean) {

        hbaseClient = new HBaseClient();
        try {
            hbaseClient.initializeHBase(hbaseConfigBean);
            LOGGER.debug("HBase client initialized!");

            eCountDAO = new EmailRecipientCountDAO(hbaseClient);

            try {

                // Createt Hbase Table (tenantname:emailrecipientcount)
                eCountDAO.createTable();

                //Publish sample data into Hbase table
                publishSampleRecords();

                // Fetch Hbase tabe records
                List<EmailRecipientCount> records = getHbaseRecords();

            } catch (Exception ex) {
                LOGGER.error("Hbase operations failed",ex);
            }

        } catch (Exception ex) {
            LOGGER.error("Failed to initialized Hbase client", ex);

        }

    }

    public void insertRecord(EmailRecipientCount emailRecipientCount) {

        try {
            eCountDAO.insert(emailRecipientCount);
        } catch (IOException ex) {
            LOGGER.error("Failed to insert record into hbase", ex);

        }

    }

    public void publishSampleRecords() {
        EmailRecipientCount emailRecipientCount = new EmailRecipientCount();
        emailRecipientCount.setPk("mkumar@securonix.com");
        emailRecipientCount.setEmailRecipient("mkumar@securonix.com");
        emailRecipientCount.setCount(3);
        insertRecord(emailRecipientCount);

    }

    public List<EmailRecipientCount> getHbaseRecords() {
        final Filter filter = null;
        List<EmailRecipientCount> list = new ArrayList<>();
        try {
            list = eCountDAO.read(filter);
        } catch (IOException ex) {
            LOGGER.error("Failed to get record from hbase", ex);
        }

        return list;
    }

    /**
     * Fetch records from Hbase table
     *
     * @param table : Hbase table name
     * @return List of Hbase records
     */
    public List getHbaseRecords(String table) {
        List<Object> records = null;
        try {
            if (table.contains(":")) {
                table = table.substring(table.indexOf(":") + 1);
            }
            Long policyID = 0L;
            //Get the substring for policyviolationdetails table
            if (table.contains(TABLE_VIOLATIONS)) {
                policyID = Long.parseLong(table.substring(table.indexOf("_") + 1));
                table = table.substring(0, table.indexOf("_"));
            }

            LOGGER.debug("Reading data from HBase for " + table);

            // initialize DAO
            AbstractTableDAO sed = null;

            switch (table) {
                case HBaseConstants.TABLE_SNYPR_ERRORS:
                    sed = new SnyperErrorDAO(hbaseClient);
                    break;
                case TABLE_VIOLATIONS:
                    sed = new ViolationDAO(hbaseClient);
                    break;
                case HBaseConstants.TABLE_OFFSET_CHECKPOINT:
                    sed = new KafkaOffsetDAO(hbaseClient);
                    break;
            }

            if (sed == null) {
                if (table.equals(TABLE_CORRELATION_RULES_H)) {
                    CorrelationRulesHDAO crDao = new CorrelationRulesHDAO(hbaseClient);
                    records = crDao.getData(Long.MIN_VALUE, Long.MAX_VALUE);
                } else {
                    records = new ArrayList<>();
                }
            } else {
                LOGGER.debug("DAO obtained- " + sed.getClass());
                if (table.equals(TABLE_VIOLATIONS)) {
                    List<MiniEEO> lstViolations = null;
                    ViolationDAO vDAO = (ViolationDAO) sed;
                    lstViolations = vDAO.readFromD(null, Long.MIN_VALUE, Long.MAX_VALUE, policyID);
                    return lstViolations;
                } else {
                    records = sed.read(Long.MIN_VALUE, Long.MAX_VALUE);
                }
            }
        } catch (NumberFormatException | IOException ex) {
            LOGGER.error("Failed to get record from Hbase ", ex);

        }
        LOGGER.debug("Records obtained- " + records != null);

        return records;

    }
}
