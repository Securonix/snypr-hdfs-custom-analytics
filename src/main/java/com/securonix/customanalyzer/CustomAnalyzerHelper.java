package com.securonix.customanalyzer;

import com.securonix.application.common.Constants;
import com.securonix.application.common.JAXBUtilImpl;
import com.securonix.application.hibernate.tables.Configxml;
import com.securonix.application.hibernate.tables.PolicyMaster;
import com.securonix.application.hibernate.tables.Policymastercategory;
import com.securonix.application.hibernate.tables.PolicymastercategoryId;
import com.securonix.application.hibernate.tables.Resourcegroups;
import com.securonix.application.hibernate.tables.RiskType;
import com.securonix.application.hibernate.util.DbUtil;
import com.securonix.application.policy.PolicyConstants;
import com.securonix.application.risk.dataAccess.uiUtil.RiskUtilImpl;
import com.securonix.kafkaclient.KafkaClient;
import static com.securonix.kafkaclient.KafkaClient.CF_ACTION_POLICY_UPDATED;
import static com.securonix.kafkaclient.KafkaClient.CF_ORIGINATOR_POLICY_ENGINE;
import com.securonix.snyper.policy.beans.ViolationDisplayConfigBean;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;


/**
 * Helper class for custom analyzer
 *
 * @author Securonix Inc.
 */
public class CustomAnalyzerHelper {

    /**
     * Logger for the class
     */
    private final static Logger LOGGER = LogManager.getLogger();

    /**
     * Creates policy with the given inputs
     *
     * @param policyName Unique name for the policy
     * @param functionality Functionality type
     * @param categoryId Category Id
     * @param riskThreatName Threat name
     * @param criticality Criticality for the policy
     * @param violator Violation entity
     *
     * @return Policy object
     */
    public static PolicyMaster createPolicy(String policyName, String functionality, int categoryId, String riskThreatName, String criticality, String violator,
            Map<String, String> violationInfo) {

        final long riskThreatId = RiskUtilImpl.getRiskThreatId(riskThreatName, "Medium", null);

        final Date currentTime = new Date();

        final PolicyMaster policy = new PolicyMaster();
        policy.setResourceGroupId(-1L);
        policy.setResourcetypeid(-1L);
        policy.setName(policyName);
        policy.setDescription("Created by custom spark job - " + currentTime);

        policy.setFunctionality(functionality);
        policy.setThreatname(riskThreatName);
        policy.setRiskthreatid(riskThreatId);
        policy.setLastUpdated(currentTime);

        policy.setType(PolicyConstants.TYPE_HDFS);
        policy.setCriticality(criticality);
        policy.setAnalyticstype("CUSTOM");
        policy.setTargetWorkflow("PolicyOutlierWorkflow");
        policy.setWeight(1l);

        policy.setCreatedBy("admin");
        policy.setUpdatedBy("admin");
        policy.setViolator(violator);

        policy.setDashboardDisplay(true);
        policy.setEnabled(true);

        final ArrayList<Integer> categoryIds = new ArrayList();
        categoryIds.add(categoryId);
        
        policy.setCategoryid(categoryId);

        policy.setCategory(getCategoryName(categoryId));
        savePolicy(policy, categoryIds, violationInfo);

        LOGGER.info("POLICY CREATED WITH ID:{}", policy.getId());

        // inform Spark jobs to load the newly created policy
        KafkaClient.INSTANCE.publishControlFlag(policy.getId(), CF_ORIGINATOR_POLICY_ENGINE, CF_ACTION_POLICY_UPDATED);
        LOGGER.info("Control flag signalled to Kafka");

        return policy;
    }

    /**
     * Saves policy to the database (policy_master table) and also update Policymastercategory table.
     *
     * @param policy Policy to be saved
     * @param categoryIds Category Id for the policy
     */
    private static void savePolicy(final PolicyMaster policy, final ArrayList<Integer> categoryIds, Map<String, String> violationInfo) {

        final String verboseInfo = violationInfo.get("verboseinformation");
        if (verboseInfo != null) {
            policy.setVerboseinfotemplate(verboseInfo);
        }

        final ViolationDisplayConfigBean vdcb = new ViolationDisplayConfigBean();

        if (violationInfo.containsKey("GROUPING_ATTRIBUTE")) {

            vdcb.setDisplayAttributes(new ArrayList<String>() {
                {
                    add(violationInfo.get("GROUPING_ATTRIBUTE"));
                }
            });

            final ArrayList<String> metadataAttributes = new ArrayList<>();
            if (violationInfo.containsKey("LEVEL1_MetadataAttribute1")) {
                metadataAttributes.add(violationInfo.get("LEVEL1_MetadataAttribute1"));
            }
            if (violationInfo.containsKey("LEVEL1_MetadataAttribute2")) {
                metadataAttributes.add(violationInfo.get("LEVEL1_MetadataAttribute2"));
            }
            if (violationInfo.containsKey("LEVEL1_MetadataAttribute3")) {
                metadataAttributes.add(violationInfo.get("LEVEL1_MetadataAttribute3"));
            }

            if (!metadataAttributes.isEmpty()) {
                vdcb.setMetadataAttributes(metadataAttributes);
            }
        }

        if (violationInfo.containsKey("LEVEL2_PrimaryAttribute")) {
            vdcb.setLevel2Attributes(violationInfo.get("LEVEL2_PrimaryAttribute"));

            final ArrayList<String> level2MetaDataAttr = new ArrayList<>();
            if (violationInfo.containsKey("LEVEL2_MetadataAttribute1")) {
                level2MetaDataAttr.add(violationInfo.get("LEVEL2_MetadataAttribute1"));
            }
            if (violationInfo.containsKey("LEVEL2_MetadataAttribute2")) {
                level2MetaDataAttr.add(violationInfo.get("LEVEL2_MetadataAttribute2"));
            }
            if (violationInfo.containsKey("LEVEL2_MetadataAttribute3")) {
                level2MetaDataAttr.add(violationInfo.get("LEVEL2_MetadataAttribute3"));
            }

            if (!level2MetaDataAttr.isEmpty()) {
                vdcb.setLevel2MetaDataAttr(level2MetaDataAttr);
            }
        }
        
        final List<ViolationDisplayConfigBean> violationInfoList = new ArrayList<>();
        violationInfoList.add(vdcb);

        final String xml = JAXBUtilImpl.pojosToXml(violationInfoList, ViolationDisplayConfigBean.class);
        policy.setViolationdisplayconfig(xml);

        policy.setSignatureid(getSignatureId());

        final long riskTypeId = createRiskType(policy, "Policy");
        policy.setRiskTypeId(riskTypeId);
        DbUtil.saveTable(policy);

        // Update Policymastercategory
        if (categoryIds != null) {

            String query = "delete Policymastercategory where id.policyid = :policyid ";
            final Map<String, Object> parameters = new HashMap<>();
            parameters.put("policyid", policy.getId());
            try {
                DbUtil.executeHQLQuery(query, parameters, true);
                LOGGER.debug("Older categories deleted");
            } catch (Exception ex) {
                LOGGER.error("Error: ", ex);
            }

            for (Integer categoryId : categoryIds) {
                Policymastercategory pcDB = new Policymastercategory();
                pcDB.setId(new PolicymastercategoryId(policy.getId(), categoryId));
                pcDB.setRiskthreatid(policy.getRiskthreatid());
                pcDB.setRisktypeid(policy.getRiskTypeId());
                pcDB.setCategory(getCategoryName(categoryId));
                DbUtil.saveTable(pcDB);
            }
        }
    }

    /**
     * Forms and returns signature Id for the policy
     *
     * @return Signature for the policy
     */
    private static String getSignatureId() {

        String currentsignatureId = getConfigXml(Constants.POLICY_SIGNATURE_ID);
        if (currentsignatureId == null || currentsignatureId.trim().isEmpty()) {
            currentsignatureId = "1000000";
        }

        Long signatureId = Long.parseLong(currentsignatureId);
        signatureId++;

        updateConfigXml(Constants.POLICY_SIGNATURE_ID, signatureId.toString());
        return signatureId.toString();
    }

    /**
     * Utility method to update config in the database
     *
     * @param xmlkey Key for the config
     * @param xmlvalue Configuration in XML format
     */
    private static void updateConfigXml(String xmlkey, String xmlvalue) {
        final Configxml configxml = new Configxml();
        configxml.setXmlkey(xmlkey);
        configxml.setXmlvalue(xmlvalue.trim());
        DbUtil.saveTable(configxml);
    }

    /**
     * Utility method to read and return configuration from the database for the given key
     *
     * @param xmlkey Configuration key
     *
     * @return Configuration for the given key
     */
    private static String getConfigXml(String xmlkey) {

        final Map<String, Object> parameters = new HashMap<>();
        parameters.put("xmlkey", xmlkey);

        final List<String> xmlValues = DbUtil.executeHQLQuery("SELECT xmlvalue FROM Configxml where xmlkey=:xmlkey", parameters, false);
        return xmlValues == null || xmlValues.isEmpty() ? null : xmlValues.get(0);
    }

    /**
     * Creates risk type for the policy
     *
     * @param policy Policy
     * @param source Source
     *
     * @return Risk type Id
     */
    private static long createRiskType(final PolicyMaster policy, final String source) {

        final RiskType type = new RiskType();
        type.setSource(source);
        type.setRiskname(policy.getName() + " Risk");
        DbUtil.saveTable(type);

        return type.getId();
    }

    /**
     * Reads and returns category name from the database for the given Id
     *
     * @param catid Category Id
     *
     * @return Name for the given category Id
     */
    private static String getCategoryName(Integer catid) {

        final Map<String, Object> parameters = new HashMap<>();
        parameters.put("catid", catid);

        final String query = "select categoryname from Policycategory where id=:catid";
        final List categorynames = DbUtil.executeHQLQuery(query, parameters, false);

        return categorynames.size() > 0 ? (String) categorynames.get(0) : "";
    }

    /**
     * Returns resource groups for the functionality
     *
     * @param functionality Functionality type
     *
     * @return List of resource group Ids for the given functionality type
     */
    public static List<Long> getResourceGroupsForFunctionality(final String functionality) {

        final List<Long> rgIds = new ArrayList();

        final List<Resourcegroups> rgList = DbUtil.executeHQLQuery("from Resourcegroups where functionality = '" + functionality + "'");
        rgList.forEach(rg -> {
            rgIds.add(rg.getId());
        });

        return rgIds;
    }

    public static Map<String, String> readViolationInfoProperties(final Properties props) {

        final Map<String, String> map = new HashMap<>();

        final String verboseInfo = props.getProperty("verboseinformation");
        if (verboseInfo != null && !verboseInfo.trim().isEmpty()) {
            map.put("verboseinformation", verboseInfo.trim());
        }

        final String groupingAttribute = props.getProperty("GROUPING_ATTRIBUTE");
        final String l1MetaAttribute1 = props.getProperty("LEVEL1_MetadataAttribute1");
        final String l1MetaAttribute2 = props.getProperty("LEVEL1_MetadataAttribute2");
        final String l1MetaAttribute3 = props.getProperty("LEVEL1_MetadataAttribute3");

        final String l2PrimaryAttribute = props.getProperty("LEVEL2_PrimaryAttribute");
        final String l2MetaAttribute1 = props.getProperty("LEVEL2_MetadataAttribute1");
        final String l2MetaAttribute2 = props.getProperty("LEVEL2_MetadataAttribute2");
        final String l2MetaAttribute3 = props.getProperty("LEVEL2_MetadataAttribute3");

        if (groupingAttribute != null && !groupingAttribute.trim().isEmpty()) {
            map.put("GROUPING_ATTRIBUTE", groupingAttribute.trim());
        }
        if (l1MetaAttribute1 != null && !l1MetaAttribute1.trim().isEmpty()) {
            map.put("LEVEL1_MetadataAttribute1", l1MetaAttribute1.trim());
        }
        if (l1MetaAttribute2 != null && !l1MetaAttribute2.trim().isEmpty()) {
            map.put("LEVEL1_MetadataAttribute2", l1MetaAttribute2.trim());
        }
        if (l1MetaAttribute3 != null && !l1MetaAttribute3.trim().isEmpty()) {
            map.put("LEVEL1_MetadataAttribute3", l1MetaAttribute3.trim());
        }

        if (l2PrimaryAttribute != null && !l2PrimaryAttribute.trim().isEmpty()) {
            map.put("LEVEL2_PrimaryAttribute", l2PrimaryAttribute.trim());
        }
        if (l2MetaAttribute1 != null && !l2MetaAttribute1.trim().isEmpty()) {
            map.put("LEVEL2_MetadataAttribute1", l2MetaAttribute1.trim());
        }
        if (l2MetaAttribute2 != null && !l2MetaAttribute2.trim().isEmpty()) {
            map.put("LEVEL2_MetadataAttribute2", l2MetaAttribute2.trim());
        }
        if (l2MetaAttribute3 != null && !l2MetaAttribute3.trim().isEmpty()) {
            map.put("LEVEL2_MetadataAttribute3", l2MetaAttribute3.trim());
        }

        return map;
    }
}
