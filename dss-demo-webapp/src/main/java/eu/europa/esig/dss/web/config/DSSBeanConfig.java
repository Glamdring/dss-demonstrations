package eu.europa.esig.dss.web.config;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;

import javax.sql.DataSource;

import org.apache.http.ssl.SSLContexts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.io.ClassPathResource;

import com.logsentinel.LogSentinelClient;
import com.logsentinel.LogSentinelClientBuilder;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;

import eu.europa.esig.dss.asic.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.client.crl.JdbcCacheCRLSource;
import eu.europa.esig.dss.client.crl.OnlineCRLSource;
import eu.europa.esig.dss.client.http.DataLoader;
import eu.europa.esig.dss.client.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.client.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.client.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.client.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.client.http.proxy.ProxyConfig;
import eu.europa.esig.dss.client.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.client.tsp.OnlineTSPSource;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.RemoteDocumentSignatureServiceImpl;
import eu.europa.esig.dss.signature.RemoteMultipleDocumentsSignatureServiceImpl;
import eu.europa.esig.dss.token.KeyStoreSignatureTokenConnection;
import eu.europa.esig.dss.token.RemoteSignatureTokenConnection;
import eu.europa.esig.dss.token.RemoteSignatureTokenConnectionImpl;
import eu.europa.esig.dss.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.tsl.service.TSLRepository;
import eu.europa.esig.dss.tsl.service.TSLValidationJob;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.RemoteDocumentValidationService;
import eu.europa.esig.dss.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.x509.tsp.TSPSource;
import eu.europa.esig.dss.xades.signature.XAdESService;

@Configuration
@PropertySource(value= {"classpath:dss.properties", "file:${dss.config.path}/dss.properties"}, ignoreResourceNotFound=true)
@ComponentScan(basePackages = { "eu.europa.esig.dss" })
public class DSSBeanConfig {

    private static final Logger logger = LoggerFactory.getLogger(DSSBeanConfig.class);
    
	@Value("${default.validation.policy}")
	private String defaultValidationPolicy;

	@Value("${current.lotl.url}")
	private String lotlUrl;

	@Value("${lotl.country.code}")
	private String lotlCountryCode;

	@Value("${lotl.root.scheme.info.uri}")
	private String lotlRootSchemeInfoUri;

	@Value("${current.oj.url}")
	private String ojUrl;

	@Value("${oj.content.keystore.type}")
	private String ksType;

	@Value("${oj.content.keystore.filename}")
	private String ksFilename;

	@Value("${oj.content.keystore.password}")
	private String ksPassword;

	@Value("${dss.tsa.url}")
	private String tsaUrl;

	@Value("${dss.server.signing.keystore.type}")
	private String serverSigningKeystoreType;

	@Value("${dss.server.signing.keystore.filename}")
	private String serverSigningKeystoreFilename;

	@Value("${dss.server.signing.keystore.password}")
	private String serverSigningKeystorePassword;
	
	@Value("${pdf.signature.image.dir}")
	private String signatureImageDir;

    @Value("${logsentinel.organization.id}")
    private String logsentinelOrgId;

    @Value("${logsentinel.secret}")
    private String logsentinelSecret;

    @Value("${logsentinel.app.id}")
    private String logsentinelAppId;

    @Value("${logsentinel.url}")
    private String logsentinelUrl;
    
    @Value("${logsentinel.include.names}")
    private boolean logsentinelIncludeNames;
	
    @Value("${rabbitmq.uri}")
    private String rabbitMqUri;
    
    @Value("${rabbitmq.client.keystore.path}")
    private String rabbitMqClientKeystorePath;
    
    @Value("${rabbitmq.client.keystore.pass}")
    private String rabbitMqClientKeystorePass;
    
	@Autowired
	private DataSource dataSource;

	// can be null
	@Autowired(required = false)
	private ProxyConfig proxyConfig;
	
	@Bean
	public CommonsDataLoader dataLoader() {
		CommonsDataLoader dataLoader = new CommonsDataLoader();
		dataLoader.setProxyConfig(proxyConfig);
		return dataLoader;
	}

	@Bean
	public TimestampDataLoader timestampDataLoader() {
		TimestampDataLoader timestampDataLoader = new TimestampDataLoader();
		timestampDataLoader.setProxyConfig(proxyConfig);
		return timestampDataLoader;
	}

	@Bean
	public OCSPDataLoader ocspDataLoader() {
		OCSPDataLoader ocspDataLoader = new OCSPDataLoader();
		ocspDataLoader.setProxyConfig(proxyConfig);
		return ocspDataLoader;
	}

	@Bean
	public FileCacheDataLoader fileCacheDataLoader() {
		FileCacheDataLoader fileCacheDataLoader = new FileCacheDataLoader();
		fileCacheDataLoader.setDataLoader(dataLoader());
		// Per default uses "java.io.tmpdir" property
		// fileCacheDataLoader.setFileCacheDirectory(new File("/tmp"));
		return fileCacheDataLoader;
	}

	@Bean
	public OnlineCRLSource onlineCRLSource() {
		OnlineCRLSource onlineCRLSource = new OnlineCRLSource();
		onlineCRLSource.setDataLoader(dataLoader());
		return onlineCRLSource;
	}

	@Bean
	public JdbcCacheCRLSource cachedCRLSource() throws Exception {
		JdbcCacheCRLSource jdbcCacheCRLSource = new JdbcCacheCRLSource();
		jdbcCacheCRLSource.setDataSource(dataSource);
		jdbcCacheCRLSource.setCachedSource(onlineCRLSource());
		return jdbcCacheCRLSource;
	}

	@Bean
	public OnlineOCSPSource ocspSource() {
		OnlineOCSPSource onlineOCSPSource = new OnlineOCSPSource();
		onlineOCSPSource.setDataLoader(ocspDataLoader());
		return onlineOCSPSource;
	}

	@Bean
	public TrustedListsCertificateSource trustedListSource() {
		return new TrustedListsCertificateSource();
	}

	@Bean
	public TSPSource tspSource() {
		OnlineTSPSource onlineTSPSource = new OnlineTSPSource();
		onlineTSPSource.setDataLoader(timestampDataLoader());
		onlineTSPSource.setTspServer(tsaUrl);
		return onlineTSPSource;
	}

	@Bean
	public CertificateVerifier certificateVerifier() throws Exception {
		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setTrustedCertSource(trustedListSource());
		certificateVerifier.setCrlSource(cachedCRLSource());
		certificateVerifier.setOcspSource(ocspSource());
		certificateVerifier.setDataLoader(dataLoader());
		return certificateVerifier;
	}

	@Bean
	public ClassPathResource defaultPolicy() {
		return new ClassPathResource(defaultValidationPolicy);
	}

	@Bean
	public CAdESService cadesService() throws Exception {
		CAdESService service = new CAdESService(certificateVerifier());
		service.setTspSource(tspSource());
		return service;
	}

	@Bean
	public XAdESService xadesService() throws Exception {
		XAdESService service = new XAdESService(certificateVerifier());
		service.setTspSource(tspSource());
		return service;
	}

	@Bean
	public PAdESService padesService() throws Exception {
		PAdESService service = new PAdESService(certificateVerifier());
		service.setTspSource(tspSource());
		service.setSignatureImageDir(new File(signatureImageDir));
		return service;
	}

	@Bean
	public ASiCWithCAdESService asicWithCadesService() throws Exception {
		ASiCWithCAdESService service = new ASiCWithCAdESService(certificateVerifier());
		service.setTspSource(tspSource());
		return service;
	}

	@Bean
	public ASiCWithXAdESService asicWithXadesService() throws Exception {
		ASiCWithXAdESService service = new ASiCWithXAdESService(certificateVerifier());
		service.setTspSource(tspSource());
		return service;
	}

	@Bean
	public RemoteDocumentSignatureServiceImpl remoteSignatureService() throws Exception {
		RemoteDocumentSignatureServiceImpl service = new RemoteDocumentSignatureServiceImpl();
		service.setAsicWithCAdESService(asicWithCadesService());
		service.setAsicWithXAdESService(asicWithXadesService());
		service.setCadesService(cadesService());
		service.setXadesService(xadesService());
		service.setPadesService(padesService());
		service.setLogSentinelClient(logSentinelClient());
		service.setLogsentinelIncludeNames(logsentinelIncludeNames);
		return service;
	}

	@Bean
	public RemoteMultipleDocumentsSignatureServiceImpl remoteMultipleDocumentsSignatureService() throws Exception {
		RemoteMultipleDocumentsSignatureServiceImpl service = new RemoteMultipleDocumentsSignatureServiceImpl();
		service.setAsicWithCAdESService(asicWithCadesService());
		service.setAsicWithXAdESService(asicWithXadesService());
		service.setXadesService(xadesService());
		service.setLogSentinelClient(logSentinelClient());
        service.setLogsentinelIncludeNames(logsentinelIncludeNames);
		return service;
	}

	@Bean
	public RemoteDocumentValidationService remoteValidationService() throws Exception {
		RemoteDocumentValidationService service = new RemoteDocumentValidationService();
		service.setVerifier(certificateVerifier());
		return service;
	}

	@Bean
	public KeyStoreSignatureTokenConnection remoteToken() throws IOException {
		return new KeyStoreSignatureTokenConnection(new ClassPathResource(serverSigningKeystoreFilename).getFile(), serverSigningKeystoreType,
				serverSigningKeystorePassword);
	}

	@Bean
	public RemoteSignatureTokenConnection serverToken() throws IOException {
		RemoteSignatureTokenConnectionImpl remoteSignatureTokenConnectionImpl = new RemoteSignatureTokenConnectionImpl();
		remoteSignatureTokenConnectionImpl.setToken(remoteToken());
		return remoteSignatureTokenConnectionImpl;
	}

	@Bean
	public TSLRepository tslRepository(TrustedListsCertificateSource trustedListSource) {
		TSLRepository tslRepository = new TSLRepository();
		tslRepository.setTrustedListsCertificateSource(trustedListSource);
		return tslRepository;
	}

	@Bean
	public KeyStoreCertificateSource ojContentKeyStore() throws IOException {
		return new KeyStoreCertificateSource(new ClassPathResource(ksFilename).getFile(), ksType, ksPassword);
	}

	@Bean
	public TSLValidationJob tslValidationJob(DataLoader dataLoader, TSLRepository tslRepository, KeyStoreCertificateSource ojContentKeyStore) {
		TSLValidationJob validationJob = new TSLValidationJob();
		validationJob.setDataLoader(dataLoader);
		validationJob.setRepository(tslRepository);
		validationJob.setLotlUrl(lotlUrl);
		validationJob.setLotlRootSchemeInfoUri(lotlRootSchemeInfoUri);
		validationJob.setLotlCode(lotlCountryCode);
		validationJob.setOjUrl(ojUrl);
		validationJob.setOjContentKeyStore(ojContentKeyStore);
		validationJob.setCheckLOTLSignature(true);
		validationJob.setCheckTSLSignatures(true);
		return validationJob;
	}
	
	
	@Bean(destroyMethod = "close")
	public Connection amqpConnection() throws Exception {
	    if (Utils.isStringBlank(rabbitMqUri)) {
	        return null;
	    }
	    
	    ConnectionFactory factory = new ConnectionFactory();
	    factory.setAutomaticRecoveryEnabled(true);
	    KeyStore ks = KeyStore.getInstance("PKCS12");
	    try {
	        if (!rabbitMqClientKeystorePath.isEmpty()) {
        	    ks.load(new FileInputStream(rabbitMqClientKeystorePath), rabbitMqClientKeystorePass.toCharArray());
        	    factory.useSslProtocol(SSLContexts.custom()
        	            .useProtocol("TLSv1.2")
        	            .loadKeyMaterial(ks, rabbitMqClientKeystorePass.toCharArray())
        	            .build());
	        }
	    } catch (Exception ex) {
	        logger.warn("Failed to load amqp client certificate", ex);
	    }
	    factory.setUri(rabbitMqUri);
	    try {
	        return factory.newConnection();
	    } catch (Exception ex) {
	        logger.warn("Failed to connect to rabbitmq", ex);
	        return null;
	    }
	}
	
	@Bean
	public LogSentinelClient logSentinelClient() {
	    if (Utils.isStringBlank(logsentinelOrgId)) {
	        return null;
	    }
	    
	    LogSentinelClientBuilder builder = new LogSentinelClientBuilder()
	            .setBasePath(logsentinelUrl)
	            .setApplicationId(logsentinelAppId)
	            .setOrganizationId(logsentinelOrgId)
	            .setSecret(logsentinelSecret);
	    
	    return builder.build();
	}

}