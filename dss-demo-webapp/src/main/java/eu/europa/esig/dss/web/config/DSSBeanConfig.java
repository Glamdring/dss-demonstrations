package eu.europa.esig.dss.web.config;

import java.io.FileInputStream;
import java.io.File;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.annotation.PostConstruct;
import javax.sql.DataSource;

import org.apache.http.ssl.SSLContexts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.ImportResource;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.util.StringUtils;

import com.logsentinel.LogSentinelClient;
import com.logsentinel.LogSentinelClientBuilder;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;

import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.pades.DSSDocumentAdapter;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.service.crl.JdbcCacheCRLSource;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.service.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.service.http.proxy.ProxyConfig;
import eu.europa.esig.dss.service.ocsp.JdbcCacheOCSPSource;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.token.KeyStoreSignatureTokenConnection;
import eu.europa.esig.dss.tsl.function.OfficialJournalSchemeInformationURI;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.ws.cert.validation.common.RemoteCertificateValidationService;
import eu.europa.esig.dss.ws.server.signing.common.RemoteSignatureTokenConnection;
import eu.europa.esig.dss.ws.server.signing.common.RemoteSignatureTokenConnectionImpl;
import eu.europa.esig.dss.ws.signature.common.RemoteDocumentSignatureServiceImpl;
import eu.europa.esig.dss.ws.signature.common.RemoteMultipleDocumentsSignatureServiceImpl;
import eu.europa.esig.dss.ws.timestamp.remote.RemoteTimestampService;
import eu.europa.esig.dss.ws.validation.common.RemoteDocumentValidationService;
import eu.europa.esig.dss.ws.validation.common.ReportSigner;
import eu.europa.esig.dss.xades.signature.XAdESService;

@Configuration
@PropertySource(value= {"classpath:dss.properties", "file:${dss.config.path}/dss.properties"}, ignoreResourceNotFound=true)
@ComponentScan(basePackages = { "eu.europa.esig.dss.web.job", "eu.europa.esig.dss.web.service" })
@Import({ PropertiesConfig.class, CXFConfig.class, PersistenceConfig.class, ProxyConfiguration.class, WebSecurityConfig.class,
		SchedulingConfig.class })
@ImportResource({ "${tsp-source}" })
public class DSSBeanConfig {

    private static final Logger LOG = LoggerFactory.getLogger(DSSBeanConfig.class);
    
	@Value("${default.validation.policy}")
	private String defaultValidationPolicy;

	@Value("${current.lotl.url}")
	private String lotlUrl;

	@Value("${lotl.country.code}")
	private String lotlCountryCode;

	@Value("${current.oj.url}")
	private String currentOjUrl;

	@Value("${oj.content.keystore.type}")
	private String ksType;

	@Value("${oj.content.keystore.filename}")
	private String ksFilename;

	@Value("${oj.content.keystore.password}")
	private String ksPassword;

	@Value("${dss.server.signing.keystore.type}")
	private String serverSigningKeystoreType;

	@Value("${dss.server.signing.keystore.filename}")
	private String serverSigningKeystoreFilename;

	@Value("${dss.server.signing.keystore.password}")
	private String serverSigningKeystorePassword;
	
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
    
    @Value("${validation.signing.certificate.jks}")
    private String signingCertificateJksPath;
    
    @Value("${validation.signing.certificate.jks.pass}")
    private String signingCertificateJksPass;
    
    @Value("${rabbitmq.exchange}")
    private String rabbitMqExchange;
    
    @Value("${rabbitmq.routingKey}")
    private String rabbitMqRoutingKey;
    
    @Value("${pdf.signature.image.dir}")
    private String signatureImageDir;
    
    @Value("${validation.signing.image.x}")
    private int validationSigningImageX;
    
    @Value("${validation.signing.image.y}")
    private int validationSigningImageY;
    
    @Value("${validation.signing.image.width}")
    private int validationSigningImageWidth;
    
    @Value("${validation.signing.image.height}")
    private int validationSigningImageHeight;
    
    @Autowired
    private TSPSource tspSource;
    
	@Autowired
	private DataSource dataSource;

	@Autowired
    private PAdESService padesService;
	
	@Autowired
    private XAdESService xadesService;
	
	// can be null
	@Autowired(required = false)
	private ProxyConfig proxyConfig;
	
	@PostConstruct
	public void init() {
	    DSSDocumentAdapter.imageDir = signatureImageDir;
	}
	
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
	public JdbcCacheCRLSource cachedCRLSource() {
		JdbcCacheCRLSource jdbcCacheCRLSource = new JdbcCacheCRLSource();
		jdbcCacheCRLSource.setDataSource(dataSource);
		jdbcCacheCRLSource.setProxySource(onlineCRLSource());
		jdbcCacheCRLSource.setDefaultNextUpdateDelay((long) (60 * 3)); // 3 minutes
		return jdbcCacheCRLSource;
	}

	@Bean
	public OnlineOCSPSource onlineOcspSource() {
		OnlineOCSPSource onlineOCSPSource = new OnlineOCSPSource();
		onlineOCSPSource.setDataLoader(ocspDataLoader());
		return onlineOCSPSource;
	}

	@Bean
	public JdbcCacheOCSPSource cachedOCSPSource() {
		JdbcCacheOCSPSource jdbcCacheOCSPSource = new JdbcCacheOCSPSource();
		jdbcCacheOCSPSource.setDataSource(dataSource);
		jdbcCacheOCSPSource.setProxySource(onlineOcspSource());
		jdbcCacheOCSPSource.setDefaultNextUpdateDelay((long) (1000 * 60 * 3)); // 3 minutes
		return jdbcCacheOCSPSource;
	}

	@Bean(name = "european-trusted-list-certificate-source")
	public TrustedListsCertificateSource trustedListSource() {
		return new TrustedListsCertificateSource();
	}

	@Bean
	public CertificateVerifier certificateVerifier() throws Exception {
		CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setCrlSource(cachedCRLSource());
		certificateVerifier.setOcspSource(cachedOCSPSource());
		certificateVerifier.setDataLoader(dataLoader());
		certificateVerifier.setTrustedCertSources(trustedListSource());
		return certificateVerifier;
	}
	
	@Bean
    public ReportSigner reportSigner() throws Exception {
        ReportSigner reportSigner = new ReportSigner();
        if (!StringUtils.isEmpty(signingCertificateJksPath)) {
            try {
                KeyStore store = KeyStore.getInstance("JKS");
                store.load(new FileInputStream(signingCertificateJksPath), signingCertificateJksPass.toCharArray());
                Enumeration<String> aliases = store.aliases();
                X509Certificate signingCertificate = (X509Certificate) store.getCertificate(aliases.nextElement());
                Certificate[] signingCertificateChain = new Certificate[store.size() - 1];
                int i = 0;
                while (aliases.hasMoreElements()) {
                    signingCertificateChain[i++] = store.getCertificate(aliases.nextElement());
                }
                reportSigner.setSigningCertificate(signingCertificate);
                reportSigner.setSigningCertificateChain(signingCertificateChain);
                reportSigner.setAmqpConnection(amqpConnection());
                reportSigner.setPadesService(padesService);
                reportSigner.setXadesService(xadesService);
                reportSigner.setRabbitMqExchange(rabbitMqExchange);
                reportSigner.setRabbitMqRoutingKey(rabbitMqRoutingKey);
                reportSigner.setSignatureImageDir(signatureImageDir);
                reportSigner.setSigningCertificateJksPass(signingCertificateJksPass);
                reportSigner.setSigningCertificateJksPath(signingCertificateJksPath);
                reportSigner.setX(validationSigningImageX);
                reportSigner.setY(validationSigningImageY);
                reportSigner.setWidth(validationSigningImageWidth);
                reportSigner.setHeight(validationSigningImageHeight);
            } catch (Exception ex) {
                LOG.warn("Failed to find validation certificate from path " + signingCertificateJksPath, ex);
            }
        }
        return reportSigner;
    }

	@Bean
	public ClassPathResource defaultPolicy() {
		return new ClassPathResource(defaultValidationPolicy);
	}

	@Bean
	public CAdESService cadesService() throws Exception {
		CAdESService service = new CAdESService(certificateVerifier());
		service.setTspSource(tspSource);
		return service;
	}

	@Bean
	public XAdESService xadesService() throws Exception {
		XAdESService service = new XAdESService(certificateVerifier());
		service.setTspSource(tspSource);
		return service;
	}

	@Bean
	public PAdESService padesService() throws Exception {
		PAdESService service = new PAdESService(certificateVerifier());
		service.setTspSource(tspSource);
		return service;
	}

	@Bean
	public ASiCWithCAdESService asicWithCadesService() throws Exception {
		ASiCWithCAdESService service = new ASiCWithCAdESService(certificateVerifier());
		service.setTspSource(tspSource);
		return service;
	}

	@Bean
	public ASiCWithXAdESService asicWithXadesService() throws Exception {
		ASiCWithXAdESService service = new ASiCWithXAdESService(certificateVerifier());
		service.setTspSource(tspSource);
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
		service.setReportSigner(reportSigner());
		return service;
	}
	
	@Bean
	public RemoteCertificateValidationService RemoteCertificateValidationService() throws Exception {
		RemoteCertificateValidationService service = new RemoteCertificateValidationService();
		service.setVerifier(certificateVerifier());
		return service;
	}

	@Bean
	public KeyStoreSignatureTokenConnection remoteToken() throws IOException {
		return new KeyStoreSignatureTokenConnection(new ClassPathResource(serverSigningKeystoreFilename).getFile(), serverSigningKeystoreType,
				new PasswordProtection(serverSigningKeystorePassword.toCharArray()));
	}

	@Bean
	public RemoteSignatureTokenConnection serverToken() throws IOException {
		RemoteSignatureTokenConnectionImpl remoteSignatureTokenConnectionImpl = new RemoteSignatureTokenConnectionImpl();
		remoteSignatureTokenConnectionImpl.setToken(remoteToken());
		return remoteSignatureTokenConnectionImpl;
	}
	
	@Bean
	public RemoteTimestampService timestampService() throws IOException {
		RemoteTimestampService timestampService = new RemoteTimestampService();
		timestampService.setTSPSource(tspSource);
		return timestampService;
	}

	@Bean
	public KeyStoreCertificateSource ojContentKeyStore() {
		try {
			return new KeyStoreCertificateSource(new ClassPathResource(ksFilename).getFile(), ksType, ksPassword);
		} catch (IOException e) {
			throw new DSSException("Unable to load the file " + ksFilename, e);
		}
	}
	
	@Bean 
	public TLValidationJob job() {
		TLValidationJob job = new TLValidationJob();
		job.setTrustedListCertificateSource(trustedListSource());
		job.setListOfTrustedListSources(europeanLOTL());
		job.setOfflineDataLoader(offlineLoader());
		job.setOnlineDataLoader(onlineLoader());
		return job;
	}

	@Bean
	public DSSFileLoader onlineLoader() {
		FileCacheDataLoader offlineFileLoader = new FileCacheDataLoader();
		offlineFileLoader.setCacheExpirationTime(0);
		offlineFileLoader.setDataLoader(dataLoader());
		offlineFileLoader.setFileCacheDirectory(tlCacheDirectory());
		return offlineFileLoader;
	}

	@Bean(name = "european-lotl-source")
	public LOTLSource europeanLOTL() {
		LOTLSource lotlSource = new LOTLSource();
		lotlSource.setUrl(lotlUrl);
		lotlSource.setCertificateSource(ojContentKeyStore());
		lotlSource.setSigningCertificatesAnnouncementPredicate(new OfficialJournalSchemeInformationURI(currentOjUrl));
		lotlSource.setPivotSupport(true);
		return lotlSource;
	}

	@Bean
	public DSSFileLoader offlineLoader() {
		FileCacheDataLoader offlineFileLoader = new FileCacheDataLoader();
		offlineFileLoader.setCacheExpirationTime(Long.MAX_VALUE);
		offlineFileLoader.setDataLoader(new IgnoreDataLoader());
		offlineFileLoader.setFileCacheDirectory(tlCacheDirectory());
		return offlineFileLoader;
	}

	@Bean
	public File tlCacheDirectory() {
		File rootFolder = new File(System.getProperty("java.io.tmpdir"));
		File tslCache = new File(rootFolder, "dss-tsl-loader");
		if (tslCache.mkdirs()) {
			LOG.info("TL Cache folder : {}", tslCache.getAbsolutePath());
		}
		return tslCache;
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
	        LOG.warn("Failed to load amqp client certificate", ex);
	    }
	    factory.setUri(rabbitMqUri);
	    try {
	        return factory.newConnection();
	    } catch (Exception ex) {
	        LOG.warn("Failed to connect to rabbitmq", ex);
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