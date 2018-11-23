/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.securonix.customanalyzer.hbaseutil.dao;


import com.securonix.hbaseutil.HBaseClient;
import static com.securonix.hbaseutil.HBaseConstants.FAMILY_STATUS;
import com.securonix.hbaseutil.HBaseException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.apache.hadoop.hbase.client.Put;
import org.apache.hadoop.hbase.client.Result;
import org.apache.hadoop.hbase.client.ResultScanner;
import org.apache.hadoop.hbase.client.Scan;
import org.apache.hadoop.hbase.client.Table;
import org.apache.hadoop.hbase.filter.BinaryComparator;
import org.apache.hadoop.hbase.filter.CompareFilter;
import org.apache.hadoop.hbase.filter.Filter;
import org.apache.hadoop.hbase.filter.RowFilter;
import org.apache.hadoop.hbase.util.Bytes;
import com.securonix.customanalyzer.hbaseutil.beans.EmailRecipientCount;
import com.securonix.hbaseutil.dao.AbstractTableDAO;

/**
 * DAO for Email Recipient counts table
 *
 * @author Securonix Inc.
 */
public class EmailRecipientCountDAO extends AbstractTableDAO {
    
    public static String TABLE_EMAIL_RECIPIENT_COUNT = "emailrecipientcount";


    @Override
    public void insertSet(Set<?> list) throws IOException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    private static enum COLUMN {

        count, emailRecipient
    }

    public EmailRecipientCountDAO(final HBaseClient hbaseClient) {
        super(hbaseClient, TABLE_EMAIL_RECIPIENT_COUNT, FAMILY_STATUS);
    }

    @Override
    public Object read(final String key) throws IOException {

        EmailRecipientCount emailRecipientCount = null;

        try (final Table t = connection.getTable(tableName)) {
            Scan scan = new Scan();

            final Filter filter = new RowFilter(CompareFilter.CompareOp.EQUAL, new BinaryComparator(Bytes.toBytes(key)));
            scan.setFilter(filter);

            try (final ResultScanner scanner = t.getScanner(scan);) {
                for (Result res : scanner) {
                    emailRecipientCount = retrieveRecord(res);
                }
            }
        }

        return emailRecipientCount;
    }

    @Override
    public List read(final Filter filter) throws IOException {

        final List<EmailRecipientCount> result = new ArrayList<>();

        try (final Table t = connection.getTable(tableName)) {

            final Scan scan = new Scan();
            if (filter != null) {
                scan.setFilter(filter);
            }

            try (final ResultScanner scanner = t.getScanner(scan);) {
                for (Result res : scanner) {
                    result.add(retrieveRecord(res));
                }
            }
        }

        return result;
    }

    @Override
    public EmailRecipientCount retrieveRecord(final Result res) {

        final String count = Bytes.toString(res.getValue(familyBytes, COUNT));
        final String emailRecipient = Bytes.toString(res.getValue(familyBytes, EMAIL_RECIPIENT));
        final String key = Bytes.toString(res.getRow());

        final EmailRecipientCount emailRecipientCountObject = new EmailRecipientCount();

        emailRecipientCountObject.setCount(Long.parseLong(getValue(count)));
        emailRecipientCountObject.setEmailRecipient(emailRecipient);
        emailRecipientCountObject.setPk(key);

        return emailRecipientCountObject;
    }

    private final static byte[] COUNT = Bytes.toBytes(COLUMN.count.toString());
    private final static byte[] EMAIL_RECIPIENT = Bytes.toBytes(COLUMN.emailRecipient.toString());

    
    @Override
    public void createTable() {
        System.out.println("Running new createTable");
        try {
            if (!hbaseClient.tableExist(table)) {
               System.out.println("Table does not exist, creating new one- " + table);
                ArrayList<String> columnFamilies = new ArrayList<>();
                columnFamilies.add(FAMILY_STATUS);
                System.out.println("In family size:" + columnFamilies.size());
                hbaseClient.createTable(table, columnFamilies, false, 1);
            }
        } catch (Exception ex) {
            System.out.println("HBaseException"+ ex);
        }
    }

    @Override
    public void insert(Object obj) throws IOException {
        System.out.println("Inside Insert");

        EmailRecipientCount emailRecipientCount = (EmailRecipientCount) obj;

        try (final Table t = connection.getTable(tableName)) {
            System.out.println("table :"+t.getName());
            
            System.out.println("emailRecipientCount = " + emailRecipientCount.getPk());
            System.out.println("emailRecipientCount = " + emailRecipientCount.getEmailRecipient());
            System.out.println("emailRecipientCount = " + emailRecipientCount.getCount());
            System.out.println("");
                        
            final Put p = new Put(Bytes.toBytes(emailRecipientCount.getPk()));
            p.addColumn(familyBytes, COUNT, toBytes(emailRecipientCount.getCount() + ""));
            p.addColumn(familyBytes, EMAIL_RECIPIENT, toBytes(emailRecipientCount.getEmailRecipient() + ""));

            t.put(p);
        }
    }

}