package eu.europa.esig.dss.web.service;

import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.StringReader;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

import javax.imageio.ImageIO;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlRootElement;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.logsentinel.LogSentinelClient;
import com.logsentinel.model.ActionData;
import com.logsentinel.model.ActorData;
import com.logsentinel.model.ActionData.EntryTypeEnum;

import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.model.pades.SignatureImageTextParameters.SignerTextPosition;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESTimestampParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SignatureImagePageRange;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.pades.SignatureImageParameters;
import eu.europa.esig.dss.model.pades.SignatureImageParameters.VisualSignaturePagePlacement;
import eu.europa.esig.dss.model.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.model.pades.SignatureImageTextParameters.SignerTextHorizontalAlignment;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.web.WebAppUtils;
import eu.europa.esig.dss.web.model.AbstractSignatureForm;
import eu.europa.esig.dss.web.model.ExtensionForm;
import eu.europa.esig.dss.web.model.SignatureDigestForm;
import eu.europa.esig.dss.web.model.SignatureDocumentForm;
import eu.europa.esig.dss.web.model.SignatureMultipleDocumentsForm;
import eu.europa.esig.dss.web.model.TimestampForm;
import eu.europa.esig.dss.x509.tsp.MockTSPSource;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

@Component
public class SigningService {

	private static final Logger LOG = LoggerFactory.getLogger(SigningService.class);

	@Autowired
	private CAdESService cadesService;

	@Autowired
	private PAdESService padesService;

	@Autowired
	private XAdESService xadesService;

	@Autowired
	private ASiCWithCAdESService asicWithCAdESService;

	@Autowired
	private ASiCWithXAdESService asicWithXAdESService;
	
	@Autowired(required=false)
	private LogSentinelClient logSentinelClient;
	
    @Value("${logsentinel.include.names}")
    private boolean logsentinelIncludeNames;
	
	private Unmarshaller jaxbUnmarshaller = createJAXBUnmarshaller();

	@Autowired
	private TSPSource tspSource;
	
	private ExecutorService executor = Executors.newCachedThreadPool();

	public boolean isMockTSPSourceUsed() {
		return tspSource instanceof MockTSPSource;
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	public DSSDocument extend(ExtensionForm extensionForm) {
		LOG.info("Start extend signature");

		ASiCContainerType containerType = extensionForm.getContainerType();
		SignatureForm signatureForm = extensionForm.getSignatureForm();

		DSSDocument signedDocument = WebAppUtils.toDSSDocument(extensionForm.getSignedFile());
		List<DSSDocument> originalDocuments = WebAppUtils.toDSSDocuments(extensionForm.getOriginalFiles());

		DocumentSignatureService service = getSignatureService(containerType, signatureForm);

		AbstractSignatureParameters parameters = getSignatureParameters(containerType, signatureForm, null);
		parameters.setSignatureLevel(extensionForm.getSignatureLevel());

		if (Utils.isCollectionNotEmpty(originalDocuments)) {
			parameters.setDetachedContents(originalDocuments);
		}

		DSSDocument extendDocument = service.extendDocument(signedDocument, parameters);
		LOG.info("End extend signature");
		return extendDocument;
	}

	private Unmarshaller createJAXBUnmarshaller() {
        try {
            return JAXBContext.newInstance(SignatureImageParameters.class, StampImageParameters.class).createUnmarshaller();
        } catch (JAXBException e) {
            throw new RuntimeException(e);
        }
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
	public ToBeSigned getDataToSign(SignatureDocumentForm form) {
		LOG.info("Start getDataToSign with one document");
		DocumentSignatureService service = getSignatureService(form.getContainerType(), form.getSignatureForm());

		AbstractSignatureParameters parameters = fillParameters(form);

		DSSDocument toSignDocument = WebAppUtils.toDSSDocument(form.getDocumentToSign());
		ToBeSigned toBeSigned = service.getDataToSign(toSignDocument, parameters);
		LOG.info("End getDataToSign with one document");
		return toBeSigned;
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	public ToBeSigned getDataToSign(SignatureDigestForm form) {
		LOG.info("Start getDataToSign with one digest");
		DocumentSignatureService service = getSignatureService(null, form.getSignatureForm());

		AbstractSignatureParameters parameters = fillParameters(form);

		DigestDocument toSignDigest = new DigestDocument(form.getDigestAlgorithm(), form.getDigestToSign(), form.getDocumentName());
		ToBeSigned toBeSigned = service.getDataToSign(toSignDigest, parameters);
		LOG.info("End getDataToSign with one digest");
		return toBeSigned;
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	public ToBeSigned getDataToSign(SignatureMultipleDocumentsForm form) {
		LOG.info("Start getDataToSign with multiple documents");
		MultipleDocumentsSignatureService service = getASiCSignatureService(form.getSignatureForm());

		AbstractSignatureParameters parameters = fillParameters(form);

		List<DSSDocument> toSignDocuments = WebAppUtils.toDSSDocuments(form.getDocumentsToSign());
		ToBeSigned toBeSigned = service.getDataToSign(toSignDocuments, parameters);
		LOG.info("End getDataToSign with multiple documents");
		return toBeSigned;
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	public TimestampToken getContentTimestamp(SignatureDocumentForm form) {
		LOG.info("Start getContentTimestamp with one document");

		DocumentSignatureService service = getSignatureService(form.getContainerType(), form.getSignatureForm());
		AbstractSignatureParameters parameters = fillParameters(form);
		DSSDocument toSignDocument = WebAppUtils.toDSSDocument(form.getDocumentToSign());

		TimestampToken contentTimestamp = service.getContentTimestamp(toSignDocument, parameters);

		LOG.info("End getContentTimestamp with one document");
		return contentTimestamp;
	}
	
	@SuppressWarnings({ "rawtypes", "unchecked" })
	public TimestampToken getContentTimestamp(SignatureDigestForm form) {
		LOG.info("Start getContentTimestamp with one digest");

		DocumentSignatureService service = getSignatureService(null, form.getSignatureForm());
		AbstractSignatureParameters parameters = fillParameters(form);

		DigestDocument toSignDigest = new DigestDocument(form.getDigestAlgorithm(), form.getDigestToSign(), form.getDocumentName());
		TimestampToken contentTimestamp = service.getContentTimestamp(toSignDigest, parameters);

		LOG.info("End getContentTimestamp with one digest");
		return contentTimestamp;
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	public TimestampToken getContentTimestamp(SignatureMultipleDocumentsForm form) {
		LOG.info("Start getContentTimestamp with multiple documents");

		MultipleDocumentsSignatureService service = getASiCSignatureService(form.getSignatureForm());
		AbstractSignatureParameters parameters = fillParameters(form);

		TimestampToken contentTimestamp = service.getContentTimestamp(WebAppUtils.toDSSDocuments(form.getDocumentsToSign()), parameters);

		LOG.info("End getContentTimestamp with  multiple documents");
		return contentTimestamp;
	}

	public DSSDocument timestamp(TimestampForm form) {
		List<DSSDocument> dssDocuments = WebAppUtils.toDSSDocuments(form.getOriginalFiles());

		LOG.info("Start timestamp with {} document(s)", dssDocuments.size());

		DSSDocument result = null;
		ASiCContainerType containerType = form.getContainerType();
		if (containerType == null) {
			if (dssDocuments.size() > 1) {
				throw new DSSException("Only one document is allowed for PAdES");
			}
			DSSDocument toTimestampDocument = dssDocuments.get(0);
			result = padesService.timestamp(toTimestampDocument, new PAdESTimestampParameters());
		} else {
			ASiCWithCAdESTimestampParameters parameters = new ASiCWithCAdESTimestampParameters();
			parameters.aSiC().setContainerType(containerType);
			result = asicWithCAdESService.timestamp(dssDocuments, parameters);
		}

		LOG.info("End timestamp with {} document(s)", dssDocuments.size());
		return result;
	}

	private AbstractSignatureParameters fillParameters(SignatureMultipleDocumentsForm form) {
		AbstractSignatureParameters finalParameters = getASiCSignatureParameters(form.getContainerType(), form.getSignatureForm());

		fillParameters(finalParameters, form);

		return finalParameters;
	}

	private AbstractSignatureParameters fillParameters(SignatureDocumentForm form) {
		AbstractSignatureParameters parameters = getSignatureParameters(form.getContainerType(), form.getSignatureForm(), form);
		parameters.setSignaturePackaging(form.getSignaturePackaging());

		fillParameters(parameters, form);

		return parameters;
	}
	
	private AbstractSignatureParameters fillParameters(SignatureDigestForm form) {
		AbstractSignatureParameters parameters = getSignatureParameters(null, form.getSignatureForm(), null);
		parameters.setSignaturePackaging(SignaturePackaging.DETACHED);

		fillParameters(parameters, form);

		return parameters;
	}

	private void fillParameters(AbstractSignatureParameters parameters, AbstractSignatureForm form) {
		parameters.setSignatureLevel(form.getSignatureLevel());
		parameters.setDigestAlgorithm(form.getDigestAlgorithm());
		// parameters.setEncryptionAlgorithm(form.getEncryptionAlgorithm()); retrieved from certificate
		parameters.bLevel().setSigningDate(form.getSigningDate());

		parameters.setSignWithExpiredCertificate(form.isSignWithExpiredCertificate());

		if (form.getContentTimestamp() != null) {
			parameters.setContentTimestamps(Arrays.asList(WebAppUtils.toTimestampToken(form.getContentTimestamp())));
		}

		CertificateToken signingCertificate = DSSUtils.loadCertificateFromBase64EncodedString(form.getBase64Certificate());
		parameters.setSigningCertificate(signingCertificate);

		List<String> base64CertificateChain = form.getBase64CertificateChain();
		if (Utils.isCollectionNotEmpty(base64CertificateChain)) {
			List<CertificateToken> certificateChain = new LinkedList<CertificateToken>();
			for (String base64Certificate : base64CertificateChain) {
				certificateChain.add(DSSUtils.loadCertificateFromBase64EncodedString(base64Certificate));
			}
			parameters.setCertificateChain(certificateChain);
		}
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	public DSSDocument signDocument(SignatureDocumentForm form) {
		LOG.info("Start signDocument with one document");
		DocumentSignatureService service = getSignatureService(form.getContainerType(), form.getSignatureForm());

		AbstractSignatureParameters parameters = fillParameters(form);

		DSSDocument toSignDocument = WebAppUtils.toDSSDocument(form.getDocumentToSign());
		SignatureAlgorithm sigAlgorithm = SignatureAlgorithm.getAlgorithm(form.getEncryptionAlgorithm(), form.getDigestAlgorithm());
		SignatureValue signatureValue = new SignatureValue(sigAlgorithm, Utils.fromBase64(form.getBase64SignatureValue()));
		DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);
		LOG.info("End signDocument with one document");
		
		logSigningRequest(signedDocument, parameters);
		
		return signedDocument;
	}

    @SuppressWarnings({ "rawtypes", "unchecked" })
	public DSSDocument signDocument(SignatureMultipleDocumentsForm form) {
		LOG.info("Start signDocument with multiple documents");
		MultipleDocumentsSignatureService service = getASiCSignatureService(form.getSignatureForm());

		AbstractSignatureParameters parameters = fillParameters(form);

		List<DSSDocument> toSignDocuments = WebAppUtils.toDSSDocuments(form.getDocumentsToSign());
		SignatureAlgorithm sigAlgorithm = SignatureAlgorithm.getAlgorithm(form.getEncryptionAlgorithm(), form.getDigestAlgorithm());
		SignatureValue signatureValue = new SignatureValue(sigAlgorithm, Utils.fromBase64(form.getBase64SignatureValue()));
		DSSDocument signedDocument = service.signDocument(toSignDocuments, parameters, signatureValue);
		LOG.info("End signDocument with multiple documents");
		return signedDocument;
	}

    @SuppressWarnings({ "rawtypes", "unchecked" })
	public DSSDocument signDigest(SignatureDigestForm form) {
		LOG.info("Start signDigest with one digest");
		DocumentSignatureService service = getSignatureService(null, form.getSignatureForm());

		AbstractSignatureParameters parameters = fillParameters(form);

		DigestDocument toSignDigest = new DigestDocument(form.getDigestAlgorithm(), form.getDigestToSign(), form.getDocumentName());
		SignatureAlgorithm sigAlgorithm = SignatureAlgorithm.getAlgorithm(form.getEncryptionAlgorithm(), form.getDigestAlgorithm());
		SignatureValue signatureValue = new SignatureValue(sigAlgorithm, Utils.fromBase64(form.getBase64SignatureValue()));
		DSSDocument signedDocument = service.signDocument(toSignDigest, parameters, signatureValue);
		LOG.info("End signDigest with one digest");
		return signedDocument;
	}
	
	@SuppressWarnings("rawtypes")
	private DocumentSignatureService getSignatureService(ASiCContainerType containerType, SignatureForm signatureForm) {
		DocumentSignatureService service = null;
		if (containerType != null) {
			service = (DocumentSignatureService) getASiCSignatureService(signatureForm);
		} else {
			switch (signatureForm) {
			case CAdES:
				service = cadesService;
				break;
			case PAdES:
				service = padesService;
				break;
			case XAdES:
				service = xadesService;
				break;
			default:
				LOG.error("Unknow signature form : " + signatureForm);
			}
		}
		return service;
	}

	private AbstractSignatureParameters getSignatureParameters(ASiCContainerType containerType, SignatureForm signatureForm, SignatureDocumentForm form) {
		AbstractSignatureParameters parameters = null;
		if (containerType != null) {
			parameters = getASiCSignatureParameters(containerType, signatureForm);
		} else {
			switch (signatureForm) {
			case CAdES:
				parameters = new CAdESSignatureParameters();
				break;
			case PAdES:
				parameters = createPAdESParameters(form);
				break;
			case XAdES:
				parameters = new XAdESSignatureParameters();
				break;
			default:
				LOG.error("Unknow signature form : " + signatureForm);
			}
		}
		return parameters;
	}

    private PAdESSignatureParameters createPAdESParameters(SignatureDocumentForm form) {
        PAdESSignatureParameters padesParams = new PAdESSignatureParameters();
        padesParams.setContentSize(9472 * 2); // double reserved space for signature
        padesParams.bLevel().setTrustAnchorBPPolicy(false); // if set to true, signatures by trusted-list providers fail
        if (form != null) {
        	DSSDocument image = null;
        	try {
        	    if (form.getSignatureImage() != null && !form.getSignatureImage().isEmpty()) {
            		image = new InMemoryDocument(form.getSignatureImage().getBytes());
            		image.setMimeType(MimeType.fromMimeTypeString(form.getSignatureImage().getContentType()));
        	    }
        	} catch (IOException e) {
        		throw new IllegalStateException("Failed to read input file", e);
        	}
        	
        	// Supplying the XML allows for fully customizing the signature
        	if (Utils.isStringNotBlank(form.getSignatureImageXml())) {
        	    try {
                    SignatureImageParameters signatureParams = (SignatureImageParameters) jaxbUnmarshaller.unmarshal(new StringReader(form.getSignatureImageXml()));
                    padesParams.setImageParameters(signatureParams);
                    
                    if (Utils.isStringNotBlank(form.getStampImageXml())) {
                        StampImageParameters stampParams = (StampImageParameters) jaxbUnmarshaller.unmarshal(new StringReader(form.getStampImageXml()));
                        padesParams.setStampImageParameters(stampParams.getParameters());
                    }
                } catch (JAXBException e) {
                    throw new IllegalArgumentException(e);
                }
        	    
        	    
        	} else { // sample parameters without full customizability
            	if (form.getStampImagePages() != null && !form.getStampImagePages().isEmpty()) {
            		SignatureImageParameters stampParams = new SignatureImageParameters();
            		stampParams.setPagePlacement(VisualSignaturePagePlacement.RANGE);
            		stampParams.setTextParameters(new SignatureImageTextParameters());
            		stampParams.getTextParameters().setText("%CN_1%\n%CN_2%\n%CN_3%");
            		stampParams.getTextParameters().setSignerTextHorizontalAlignment(SignerTextHorizontalAlignment.RIGHT);
            		stampParams.getTextParameters().setSignerTextPosition(SignerTextPosition.FOREGROUND);
            		stampParams.setTextRightParameters(new SignatureImageTextParameters());
            		stampParams.getTextRightParameters().setText("Signature created by\nTest\nDate: %DateTimeWithTimeZone%");
            		stampParams.setPageRange(new SignatureImagePageRange());
            		stampParams.getPageRange().setPages(Arrays.asList(form.getStampImagePages().split(","))
            		                .stream()
            						.map(Integer::parseInt).collect(Collectors.toList()));
            		stampParams.setImage(image);
            		if (image != null) {
                		try {
                			BufferedImage img = ImageIO.read(image.openStream());
                			stampParams.setWidth(img.getWidth());
                			stampParams.setHeight(img.getHeight());
                		} catch (IOException e) {
                			throw new IllegalStateException("Failed to parse image", e);
                		}
            		}
            		padesParams.setStampImageParameters(Collections.singletonList(stampParams));
            	}
            	
            	if (form.getSignatureImagePage() != null && !form.getSignatureImagePage().isEmpty()) {
            		padesParams.setImageParameters(new SignatureImageParameters());
            		padesParams.getImageParameters().setTextParameters(new SignatureImageTextParameters());
                    padesParams.getImageParameters().getTextParameters().setText("%CN_1%\n%CN_2%\n%CN_3%");
                    padesParams.getImageParameters().getTextParameters().setSignerTextHorizontalAlignment(SignerTextHorizontalAlignment.RIGHT);
                    padesParams.getImageParameters().getTextParameters().setSignerTextPosition(SignerTextPosition.FOREGROUND);
                    padesParams.getImageParameters().setTextRightParameters(new SignatureImageTextParameters());
                    padesParams.getImageParameters().getTextRightParameters().setText("Signature created by\nTest\nDate: %DateTimeWithTimeZone%");
            		padesParams.getImageParameters().setPage(Integer.parseInt(form.getSignatureImagePage()));
            		if (!padesParams.getStampImageParameters().isEmpty()) {
            		    padesParams.getImageParameters()
            		        .setImage(padesParams.getStampImageParameters().get(0).getImage());
            		}
            	}
            }
        }
        return padesParams;
    }

	@SuppressWarnings("rawtypes")
	private MultipleDocumentsSignatureService getASiCSignatureService(SignatureForm signatureForm) {
		MultipleDocumentsSignatureService service = null;
		switch (signatureForm) {
		case CAdES:
			service = asicWithCAdESService;
			break;
		case XAdES:
			service = asicWithXAdESService;
			break;
		default:
			LOG.error("Unknow signature form : " + signatureForm);
		}
		return service;
	}

	private AbstractSignatureParameters getASiCSignatureParameters(ASiCContainerType containerType, SignatureForm signatureForm) {
		AbstractSignatureParameters parameters = null;
		switch (signatureForm) {
		case CAdES:
			ASiCWithCAdESSignatureParameters asicCadesParams = new ASiCWithCAdESSignatureParameters();
			asicCadesParams.aSiC().setContainerType(containerType);
			parameters = asicCadesParams;
			break;
		case XAdES:
			ASiCWithXAdESSignatureParameters asicXadesParams = new ASiCWithXAdESSignatureParameters();
			asicXadesParams.aSiC().setContainerType(containerType);
			parameters = asicXadesParams;
			break;
		default:
			LOG.error("Unknow signature form for ASiC container: " + signatureForm);
		}
		return parameters;
	}
	
	/**
	 * Send audit trail information to the LogSentinel audit trail service for secure storing
	 * 
	 * @param signedDocument
	 * @param parameters
	 */
	private void logSigningRequest(DSSDocument signedDocument, AbstractSignatureParameters params) {
        if (logSentinelClient == null) {
            return;
        }
        
        String principal = params.getSigningCertificate().getSubjectX500Principal().getName().replace("+", ",");
        LdapName ldapName;
        try {
            ldapName = new LdapName(principal);
        } catch (InvalidNameException ex) {
            throw new RuntimeException(ex);
        }
        
        ActorData actor = new ActorData().actorId(params.getSigningCertificate().getCertificate().getSerialNumber().toString());
        
        if (logsentinelIncludeNames) {
            String signerNames = ldapName.getRdns().stream()
                    .filter(rdn -> rdn.getType().equals("CN"))
                    .map(Rdn::getValue)
                    .map(String.class::cast)
                    .findFirst().orElse("");
                    
            actor.setActorDisplayName(signerNames);
        }
        
        ActionData<String> action = new ActionData<String>().action(signedDocument.getDigest(params.getDigestAlgorithm()));
        action.setAction("SIGN");
        action.setEntityType("DOCUMENT");
        if (signedDocument.getName() != null) {
            action.setEntityId(signedDocument.getName().replace(".pdf", ""));
        }
        action.setEntryType(EntryTypeEnum.BUSINESS_LOGIC_ENTRY);
        
        executor.submit(() -> {
            try {
                logSentinelClient.getAuditLogActions().log(actor, action);
            } catch (Exception ex) {
                LOG.error("Failed to log entry", ex);
            }
        });
    }
	
	@XmlRootElement
	public static final class StampImageParameters {
	    private List<SignatureImageParameters> parameters;

        public List<SignatureImageParameters> getParameters() {
            return parameters;
        }

        public void setParameters(List<SignatureImageParameters> parameters) {
            this.parameters = parameters;
        }
	}
}
