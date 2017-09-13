/* $Id: FileOutputConnector.java 991374 2013-05-31 23:04:08Z minoru $ */

/**
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.manifoldcf.agents.output.s3;

import com.amazonaws.ClientConfiguration;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.S3ClientOptions;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.s3.model.PutObjectRequest;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.manifoldcf.agents.interfaces.*;
import org.apache.manifoldcf.agents.output.BaseOutputConnector;
import org.apache.manifoldcf.agents.output.s3.security.Security;
import org.apache.manifoldcf.agents.output.s3.security.SecurityHelper;
import org.apache.manifoldcf.agents.output.s3.utils.TimeUtils;
import org.apache.manifoldcf.agents.system.Logging;
import org.apache.manifoldcf.core.interfaces.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;


public class S3OutputConnector extends BaseOutputConnector {
    public final static String INGEST_ACTIVITY = "document ingest";
    public final static String REMOVE_ACTIVITY = "document deletion";
    private static final String[] activitiesList = new String[]{INGEST_ACTIVITY, REMOVE_ACTIVITY};

    private static final String EDIT_CONFIGURATION_JS = "editConfiguration.js";
    private static final String EDIT_CONFIGURATION_HTML = "editConfiguration.html";
    private static final String VIEW_CONFIGURATION_HTML = "viewConfiguration.html";


    private AmazonS3 s3;
    private ObjectMapper om = new ObjectMapper();


    @Override
    public String[] getActivitiesList() {
        return activitiesList;
    }

    @Override
    public void connect(ConfigParams configParameters) {
        super.connect(configParameters);

        final String endpoint = configParameters.getParameter(S3ConfigParam.ENDPOINT);
        final String region = configParameters.getParameter(S3ConfigParam.REGION);
        final String bucket = configParameters.getParameter(S3ConfigParam.BUCKET);
        final String accessKey = configParameters.getParameter(S3ConfigParam.ACCESS_KEY);
        final String secretKey = configParameters.getParameter(S3ConfigParam.SECRET_KEY);

        AWSCredentials credentials = new BasicAWSCredentials(accessKey, secretKey);
        ClientConfiguration clientConfiguration = new ClientConfiguration();
        clientConfiguration.setSignerOverride("AWSS3V4SignerType");
        s3 = new AmazonS3Client(credentials, clientConfiguration);
        s3.setRegion(Region.getRegion(Regions.fromName(region)));
        s3.setEndpoint(endpoint);
        final S3ClientOptions clientOptions = S3ClientOptions.builder().setPathStyleAccess(true).build();
        s3.setS3ClientOptions(clientOptions);

    }

    @Override
    public void disconnect() throws ManifoldCFException {
        super.disconnect();
    }

    @Override
    public String check() throws ManifoldCFException {
        final String bucket = params.getParameter(S3ConfigParam.BUCKET);
        if (!s3.doesBucketExist(bucket)) {
            return "Connection not working. Bucket '" + bucket + "' does not exist. Create it manually.";
        }

        return super.check();
    }

    @Override
    public VersionContext getPipelineDescription(Specification spec) throws ManifoldCFException, ServiceInterruption {
        //TODO create versionString based on params
        return new VersionContext("", params, spec);
    }

    @Override
    public int addOrReplaceDocumentWithException(String documentURI, VersionContext outputDescription, RepositoryDocument document, String authorityNameString, IOutputAddActivity activities) throws ManifoldCFException, ServiceInterruption, IOException {
        final String bucket = params.getParameter(S3ConfigParam.BUCKET);
        final String prefix = params.getParameter(S3ConfigParam.PREFIX);
        final String metaKey = genMetaKey(prefix, documentURI);

        String errorCode = "OK";
        String errorDesc = "Buket:" + bucket + " Key:" + metaKey + "\n";

        Path doc = null;
        try {
            if (document.getBinaryLength() == 0) {
                errorCode = "REJECTED";
                errorDesc = "Empty file";
                return DOCUMENTSTATUS_REJECTED;
            }
            doc = Files.createTempFile("manifold" + System.nanoTime(), DigestUtils.sha256Hex(documentURI));
            Files.copy(document.getBinaryStream(), doc, StandardCopyOption.REPLACE_EXISTING);
            final String fileMd5Hex = getHash(doc.toFile());
            final String fileKey = genFileKey(prefix, fileMd5Hex);
            storeMetaObject(bucket, metaKey, fileKey, fileMd5Hex, documentURI, document, authorityNameString, activities);

            if(!s3.doesObjectExist(bucket, fileKey)){
                storeFileObject(doc, bucket, fileKey, fileMd5Hex, document);
            }

        } catch (Exception e) {
            String description = "Fail to send file to s3." + errorDesc;
            Logging.agents.error(description, e);
            errorCode = "FAIL";
            errorDesc = description + e.getMessage();
            return DOCUMENTSTATUS_REJECTED;
        } finally {
            if (doc != null) {
                Files.delete(doc);
            }
            activities.recordActivity(null, INGEST_ACTIVITY, new Long(document.getBinaryLength()), documentURI, errorCode, errorDesc);
        }

        return DOCUMENTSTATUS_ACCEPTED;
    }

    private void storeMetaObject(String bucket, String metaKey, String fileKey, String fileMd5Hex, String documentURI, RepositoryDocument document, String authorityNameString, IOutputAddActivity activities) throws ManifoldCFException, IOException {
        ObjectMetadata objectMetadata = new ObjectMetadata();

        Map<String, String> customMetadata = new HashMap<>();
        final Map<String, Security> securityMap = SecurityHelper.getSecurityRules(document);
        final Map<String, Security> slorSecurityMap = SecurityHelper.convertToSolrSecurityRules(securityMap, authorityNameString, activities);

        customMetadata.put("mcf_repository_security", om.writeValueAsString(securityMap));
        customMetadata.put("mcf_solr_security", om.writeValueAsString(securityMap));
        customMetadata.put("mcf_mime_type", document.getMimeType());
        customMetadata.put("mcf_filename", utfBase64(document.getFileName()));
        customMetadata.put("mcf_length_bytes", Long.toString(document.getBinaryLength()));
        customMetadata.put("mcf_created_date", TimeUtils.toISOformatAtUTC(document.getCreatedDate()));
        customMetadata.put("mcf_indexed_date", TimeUtils.toISOformatAtUTC(document.getIndexingDate()));
        customMetadata.put("mcf_modified_date", TimeUtils.toISOformatAtUTC(document.getModifiedDate()));
        customMetadata.put("mcf_authority_name", authorityNameString);
        customMetadata.put("mcf_document_uri", utfBase64(documentURI));
        customMetadata.put("file_key",fileKey);
        customMetadata.put("file_md5hex",fileMd5Hex);
        objectMetadata.setUserMetadata(customMetadata);

        Path emtyDoc = null;
        try {
            emtyDoc = Files.createTempFile("empty", null);
            final PutObjectRequest putObjectRequest = new PutObjectRequest(bucket, metaKey, emtyDoc.toFile());
            putObjectRequest.setMetadata(objectMetadata);
            s3.putObject(putObjectRequest);
        }finally {
            if (emtyDoc != null) {
                Files.delete(emtyDoc);
            }
        }
    }

    private void storeFileObject(Path doc, String bucket, String fileKey, String fileMd5Hex, RepositoryDocument document) throws IOException {
        ObjectMetadata objectMetadata = new ObjectMetadata();

        Map<String, String> customMetadata = new HashMap<>();
        customMetadata.put("mcf_mime_type", document.getMimeType());
        customMetadata.put("mcf_filename", utfBase64(document.getFileName()));
        customMetadata.put("file_length", Long.toString(document.getBinaryLength()));
        customMetadata.put("file_key",fileKey);
        customMetadata.put("file_md5hex",fileMd5Hex);
        objectMetadata.setUserMetadata(customMetadata);


        final PutObjectRequest putObjectRequest = new PutObjectRequest(bucket, fileKey, doc.toFile());
        putObjectRequest.setMetadata(objectMetadata);
        s3.putObject(putObjectRequest);
    }

    private String utfBase64(String str) {
        return new String(Base64.encodeBase64(str.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
    }

    private String genMetaKey(String prefix, String documentURI) {
        final String uid = DigestUtils.sha256Hex(documentURI);
        final String key = prefix + "meta/" + uid;
        return key;
    }

    private String genFileKey(String prefix, String hash) {
        final String key = prefix + "file/" + hash;
        return key;
    }

    private String getHash(File file) throws IOException {
        try(InputStream in = new FileInputStream(file)) {
            return DigestUtils.md5Hex(in);
        }
    }

    @Override
    public void removeDocument(String documentURI, String outputDescription, IOutputRemoveActivity activities) throws ManifoldCFException, ServiceInterruption {
        //TODO
    }

    private static Map<String, Object> getConfigurationMap(ConfigParams parameters) {
        String endpoint = parameters.getParameter(S3ConfigParam.ENDPOINT);
        String region = parameters.getParameter(S3ConfigParam.REGION);
        String bucket = parameters.getParameter(S3ConfigParam.BUCKET);
        String accessKey = parameters.getParameter(S3ConfigParam.ACCESS_KEY);
        String secretKey = parameters.getParameter(S3ConfigParam.SECRET_KEY);
        String prefix = parameters.getParameter(S3ConfigParam.PREFIX);


        if (endpoint == null) endpoint = S3ConfigParam.ENDPOINT_DEFAULT;
        if (region == null) region = S3ConfigParam.REGION_DEFAULT;
        if (bucket == null) bucket = S3ConfigParam.BUCKET_DEFAULT;
        if (accessKey == null) accessKey = S3ConfigParam.ACCESS_KEY_DEFAULT;
        if (secretKey == null) secretKey = S3ConfigParam.SECRET_KEY_DEFAULT;
        if (prefix == null) prefix = S3ConfigParam.PREFIX_DEFAULT;

        Map<String, Object> newMap = new HashMap<>();
        newMap.put("ENDPOINT", endpoint);
        newMap.put("REGION", region);
        newMap.put("BUCKET", bucket);
        newMap.put("ACCESS_KEY", accessKey);
        newMap.put("SECRET_KEY", secretKey);
        newMap.put("PREFIX", prefix);

        return newMap;
    }

    @Override
    public void viewConfiguration(IThreadContext threadContext, IHTTPOutput out, Locale locale, ConfigParams parameters) throws ManifoldCFException, IOException {
        Map<String, Object> paramMap = getConfigurationMap(parameters);
        Messages.outputResourceWithVelocity(out, locale, VIEW_CONFIGURATION_HTML, paramMap);
    }

    @Override
    public void outputConfigurationHeader(IThreadContext threadContext, IHTTPOutput out, Locale locale, ConfigParams parameters, List<String> tabsArray) throws ManifoldCFException, IOException {
        tabsArray.add(Messages.getString(locale, "S3Connector.S3TabName"));

        Map<String, Object> paramMap = getConfigurationMap(parameters);
        Messages.outputResourceWithVelocity(out, locale, EDIT_CONFIGURATION_JS, paramMap);
    }

    @Override
    public void outputConfigurationBody(IThreadContext threadContext, IHTTPOutput out, Locale locale, ConfigParams parameters, String tabName) throws ManifoldCFException, IOException {
        Map<String, Object> paramMap = getConfigurationMap(parameters);
        paramMap.put("TABNAME", tabName);
        Messages.outputResourceWithVelocity(out, locale, EDIT_CONFIGURATION_HTML, paramMap);
    }

    @Override
    public String processConfigurationPost(IThreadContext threadContext, IPostParameters variableContext, ConfigParams parameters) throws ManifoldCFException {
        String endpoint = variableContext.getParameter("endpoint");
        if (endpoint != null) parameters.setParameter(S3ConfigParam.ENDPOINT, endpoint);

        String region = variableContext.getParameter("region");
        if (region != null) parameters.setParameter(S3ConfigParam.REGION, region);

        String bucket = variableContext.getParameter("bucket");
        if (bucket != null) parameters.setParameter(S3ConfigParam.BUCKET, bucket);

        String access_key = variableContext.getParameter("access_key");
        if (access_key != null) parameters.setParameter(S3ConfigParam.ACCESS_KEY, access_key);

        String secret_key = variableContext.getParameter("secret_key");
        if (secret_key != null) parameters.setParameter(S3ConfigParam.SECRET_KEY, secret_key);

        String prefix = variableContext.getParameter("prefix");
        if (prefix != null) parameters.setParameter(S3ConfigParam.PREFIX, prefix);

        return null;
    }

    @Override
    public void noteJobComplete(IOutputNotifyActivity activities) throws ManifoldCFException, ServiceInterruption {
        // TODO
    }

}
