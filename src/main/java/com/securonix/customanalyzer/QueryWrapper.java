package com.securonix.customanalyzer;

import com.securonix.application.hibernate.tables.PolicyMaster;
import com.securonix.snyper.config.beans.HadoopConfigBean;
import com.securonix.wrapper.HDFSWrapper;
import java.io.Serializable;
import org.apache.spark.broadcast.Broadcast;

/**
 * Wrapper used to broadcast and obtain query processor on the executor
 *
 * @author Securonix Inc.
 */
public class QueryWrapper implements Serializable {

    /**
     * Query processor
     */
    private QueryProcessor processor;

    /**
     * Initializes and return query processor
     *
     * @param hcb Hadoop configuration
     * @param policy Policy configuration
     * @param solrLookupEnabled 
     * @param redisLookupEnabled
     * @param hbaseLookupEnabled
     * @param hw
     *
     * @return Query processor
     */
    public QueryProcessor getProcessor(final HadoopConfigBean hcb, final PolicyMaster policy, final boolean solrLookupEnabled, final boolean redisLookupEnabled,final boolean hbaseLookupEnabled,final Broadcast<HDFSWrapper> hw) {

        if (processor == null) {
            processor = new QueryProcessor(hcb, policy, solrLookupEnabled, redisLookupEnabled,hbaseLookupEnabled,hw);
        }

        return processor;
    } 
     
}
