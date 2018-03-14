package com.securonix.scala.customanalyzer

import com.securonix.snyper.config.beans.HadoopConfigBean
import com.securonix.application.hibernate.tables.PolicyMaster

class QueryWrapper  extends Serializable  {
  
   /**
     * Query processor
     */
    var  processor:QueryProcessor = null;

    /**
     * Initializes and return query processor
     *
     * @param hcb Hadoop configuration
     * @param policy Policy configuration
     *
     * @return Query processor
     */
    def getProcessor(hcb:HadoopConfigBean, policy:PolicyMaster): QueryProcessor = {
       if (processor == null) {
            processor = new QueryProcessor(hcb, policy);
        }

        return processor;
      
    }
}