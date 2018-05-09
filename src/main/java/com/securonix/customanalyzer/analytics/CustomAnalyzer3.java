/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.securonix.customanalyzer.analytics;

import com.securonix.solr.util.SecuronixSolrClient;
import com.securonix.snyper.config.beans.SolrConfigBean;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.solr.client.solrj.SolrQuery;
import org.apache.solr.client.solrj.SolrServerException;
import org.apache.solr.client.solrj.response.QueryResponse;
import org.apache.solr.common.SolrDocument;

/**
 *
 * @author manishkumar
 */
public class CustomAnalyzer3 {

    public static SecuronixSolrClient solrClient;

    private final static Logger LOGGER = LogManager.getLogger();
    
    /**
     * Solr Client gets initialized.
     * 
     * @param solrConfigBean Solr Configuration Bean
     */

    public void init(final SolrConfigBean solrConfigBean) {

        try {
            solrClient = new SecuronixSolrClient(solrConfigBean, null);
            LOGGER.debug("Solr client obtained");
        } catch (Exception ex) {
            LOGGER.error("Error while obtaining solr connection", ex);
        }

    }
    
    /**
     * Check for Solr Document
     * 
     * @param query : Solr Query
     * @param collection : Collection name, where to search Solr document.
     * @return True if record present,else false.
    */

    public boolean isRecordPresentInSolr(final String query, final String collection) {
        SolrQuery sQuery = new SolrQuery();
        sQuery.set("q", query);
        sQuery.set("collection", collection);
        LOGGER.debug("query to SOLR  -{}", sQuery);
        try {
            QueryResponse rsp = solrClient.query(sQuery);
            if (rsp != null) {
                LOGGER.debug("Docs sfound # {}", rsp.getResults().getNumFound());
                return true;
            } else {
                LOGGER.debug("Failed to found Solr Document");
                return false;
            }

        } catch (SolrServerException | IOException ex) {
            LOGGER.error("Failed to get Solr Document", ex);
            return false;
        }

    }

   /**
    * Fetch Solr documents for given solr query.
    * 
    * @param query : Solr Query
    * @param collection : Collection name
    * @return Lest of solr documents.
    */ 
    public List<SolrDocument> executeSolrQuery(final String query, final String collection) {

        List<SolrDocument> SolrDocumentList = null;
        SolrQuery sQuery = new SolrQuery();
        sQuery.set("q", query);
        sQuery.set("collection", collection);
        LOGGER.debug("query to SOLR  -{}", sQuery);
        try {
            QueryResponse rsp = solrClient.query(sQuery);

            if (rsp != null) {
                SolrDocumentList = new ArrayList<>();

                final Iterator<SolrDocument> iter = rsp.getResults().iterator();
                while (iter.hasNext()) {

                    SolrDocument doc = iter.next();
                    if (doc != null) {
                        SolrDocumentList.add(doc);
                    }
                }

            } else {
                LOGGER.debug("Document not found");
            }

        } catch (SolrServerException | IOException ex) {
            LOGGER.error("Failed to get Solr Document ", ex);
        }

        return SolrDocumentList;

    }

}
