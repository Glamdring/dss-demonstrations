package eu.europa.esig.dss.web.controller;

import java.awt.Font;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.validation.Valid;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.multipart.MultipartFile;

import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.RpcClient;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.RemoteDocument;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureImagePageRange;
import eu.europa.esig.dss.SignatureImageParameters;
import eu.europa.esig.dss.SignatureImageParameters.SignerTextImageVerticalAlignment;
import eu.europa.esig.dss.SignatureImageParameters.VisualSignaturePagePlacement;
import eu.europa.esig.dss.SignatureImageTextParameters;
import eu.europa.esig.dss.SignatureImageTextParameters.SignerPosition;
import eu.europa.esig.dss.SignatureImageTextParameters.SignerTextHorizontalAlignment;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.executor.ValidationLevel;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.web.WebAppUtils;
import eu.europa.esig.dss.web.editor.EnumPropertyEditor;
import eu.europa.esig.dss.web.model.ValidationForm;
import eu.europa.esig.dss.web.service.FOPService;
import eu.europa.esig.dss.web.service.XSLTService;
import eu.europa.esig.dss.x509.CertificateToken;

@Controller
@SessionAttributes({ "simpleReportXml", "detailedReportXml" })
@RequestMapping(value = "/validation")
public class ValidationController {

	private static final Logger logger = LoggerFactory.getLogger(ValidationController.class);

	private static final String VALIDATION_TILE = "validation";
	private static final String VALIDATION_EMBED_TILE = "validation-embed";
	private static final String VALIDATION_RESULT_TILE = "validation_result";
	private static final String VALIDATION_RESULT_EMBED_TILE = "validation_result-embed";

	private static final String SIMPLE_REPORT_ATTRIBUTE = "simpleReportXml";
	private static final String DETAILED_REPORT_ATTRIBUTE = "detailedReportXml";

	@Autowired
	private CertificateVerifier certificateVerifier;

	@Autowired
	private XSLTService xsltService;

	@Autowired
	private FOPService fopService;

	@Autowired
	private Resource defaultPolicy;

	@Autowired
    private PAdESService padesService;
	
	@Value("${validation.signing.certificate}")
    private String signingCertificateBase64;
	
	private X509Certificate signingCertificate;
	private CertPath signingCertificateChain;
	
	@Autowired
	private Connection amqpConnection;
	
	@Value("${rabbitmq.exchange")
	private String rabbitMqExchange;
	
	@Value("${rabbitmq.routingKey")
    private String rabbitMqRoutingKey;
	
	@PostConstruct
	public void init() throws IOException, CertificateException {
	    ByteArrayInputStream in = new ByteArrayInputStream(Base64.getDecoder().decode(signingCertificateBase64));
	    signingCertificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
	    signingCertificateChain = CertificateFactory.getInstance("X.509").generateCertPath(in);
	}
	
	@InitBinder
	public void initBinder(WebDataBinder binder) {
		binder.registerCustomEditor(ValidationLevel.class, new EnumPropertyEditor(ValidationLevel.class));
	}

	@RequestMapping(method = RequestMethod.GET)
	public String showValidationForm(Model model, HttpServletRequest request) {
		ValidationForm validationForm = new ValidationForm();
		validationForm.setValidationLevel(ValidationLevel.ARCHIVAL_DATA);
		validationForm.setDefaultPolicy(true);
		model.addAttribute("validationForm", validationForm);
		return VALIDATION_TILE;
	}
	
	@RequestMapping(method = RequestMethod.POST)
	public String validate(@ModelAttribute("validationForm") @Valid ValidationForm validationForm, BindingResult result, Model model) {
		if (result.hasErrors()) {
			return VALIDATION_TILE;
		}

		SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(WebAppUtils.toDSSDocument(validationForm.getSignedFile()));
		documentValidator.setCertificateVerifier(certificateVerifier);

		MultipartFile originalFile = validationForm.getOriginalFile();
		if ((originalFile != null) && !originalFile.isEmpty()) {
			List<DSSDocument> detachedContents = new ArrayList<DSSDocument>();
			detachedContents.add(WebAppUtils.toDSSDocument(originalFile));
			documentValidator.setDetachedContents(detachedContents);
		}
		documentValidator.setValidationLevel(validationForm.getValidationLevel());

		Reports reports = null;

		MultipartFile policyFile = validationForm.getPolicyFile();
		if (!validationForm.isDefaultPolicy() && (policyFile != null) && !policyFile.isEmpty()) {
			try {
				reports = documentValidator.validateDocument(policyFile.getInputStream());
			} catch (IOException e) {
				logger.error(e.getMessage(), e);
			}
		} else if (defaultPolicy != null) {
			InputStream dpis = null;
			try {
				dpis = defaultPolicy.getInputStream();
				reports = documentValidator.validateDocument(dpis);
			} catch (IOException e) {
				logger.error(e.getMessage(), e);
			} finally {
				Utils.closeQuietly(dpis);
			}
		} else {
			logger.error("Not correctly initialized");
		}

		// reports.print();

		String xmlSimpleReport = reports.getXmlSimpleReport();
		model.addAttribute(SIMPLE_REPORT_ATTRIBUTE, xmlSimpleReport);
		model.addAttribute("simpleReport", xsltService.generateSimpleReport(xmlSimpleReport));

		String xmlDetailedReport = reports.getXmlDetailedReport();
		model.addAttribute(DETAILED_REPORT_ATTRIBUTE, xmlDetailedReport);
		model.addAttribute("detailedReport", xsltService.generateDetailedReport(xmlDetailedReport));

		model.addAttribute("diagnosticTree", reports.getXmlDiagnosticData());

		return VALIDATION_RESULT_TILE;
	}
	
	@RequestMapping(value = "/embed", method = RequestMethod.GET)
    public String showValidationEmbedForm(Model model, HttpServletRequest request) {
        ValidationForm validationForm = new ValidationForm();
        validationForm.setValidationLevel(ValidationLevel.ARCHIVAL_DATA);
        validationForm.setDefaultPolicy(true);
        model.addAttribute("validationForm", validationForm);
        return VALIDATION_EMBED_TILE;
    }

    @RequestMapping(value = "/embed", method = RequestMethod.POST)
    public String validateEmbed(@ModelAttribute("validationForm") @Valid ValidationForm validationForm, BindingResult result, Model model) {
        if (result.hasErrors()) {
            return VALIDATION_RESULT_EMBED_TILE;
        }
        
        validate(validationForm, result, model);
        
        return VALIDATION_RESULT_EMBED_TILE;
    }

	@RequestMapping(value = "/download-simple-report")
	public void downloadSimpleReport(@RequestParam(value = "sign", required = false, defaultValue = "false") boolean sign,
	        HttpSession session, HttpServletResponse response) {
		try {
			String simpleReport = (String) session.getAttribute(SIMPLE_REPORT_ATTRIBUTE);

			response.setContentType(MimeType.PDF.getMimeTypeString());
			response.setHeader("Content-Disposition", "attachment; filename=DSS-Simple-report.pdf");

			if (sign) {
			    ByteArrayOutputStream out = new ByteArrayOutputStream();
			    fopService.generateSimpleReport(simpleReport, out);
			    signReport(out.toByteArray(), response.getOutputStream());
			} else {
			    fopService.generateSimpleReport(simpleReport, response.getOutputStream());
			}
			
		} catch (Exception e) {
			logger.error("An error occured while generating pdf for simple report : " + e.getMessage(), e);
		}
	}

    @RequestMapping(value = "/download-detailed-report")
	public void downloadDetailedReport(@RequestParam(value = "sign", required = false, defaultValue = "false") boolean sign, 
	        HttpSession session, HttpServletResponse response) {
		try {
			String detailedReport = (String) session.getAttribute(DETAILED_REPORT_ATTRIBUTE);

			response.setContentType(MimeType.PDF.getMimeTypeString());
			response.setHeader("Content-Disposition", "attachment; filename=DSS-Detailed-report.pdf");

			if (sign) {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                fopService.generateDetailedReport(detailedReport, out);
                signReport(out.toByteArray(), response.getOutputStream());
            } else {
                fopService.generateDetailedReport(detailedReport, response.getOutputStream());
            }
		} catch (Exception e) {
			logger.error("An error occured while generating pdf for detailed report : " + e.getMessage(), e);
		}
	}

    private void signReport(byte[] byteArray, OutputStream outputStream) throws IOException {
        PAdESSignatureParameters params = new PAdESSignatureParameters();
        params.bLevel().setTrustAnchorBPPolicy(true);
        params.bLevel().setSigningDate(new Date());
        params.setDigestAlgorithm(DigestAlgorithm.SHA256);
        params.setSignWithExpiredCertificate(false);
        params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
        params.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        
        params.setCertificateChain(signingCertificateChain
                .getCertificates().stream().map(c -> new CertificateToken((X509Certificate) c)).collect(Collectors.toList()));
        params.setSigningCertificate(new CertificateToken(signingCertificate));
        SignatureImageParameters stampParams = createImageParams();
        stampParams.setPagePlacement(VisualSignaturePagePlacement.RANGE);
        stampParams.setPageRange(new SignatureImagePageRange());
        stampParams.getPageRange().setAll(true);
        stampParams.getPageRange().setExcludeLast(true);
        stampParams.getPageRange().setExcludeLastCount(1);
        params.setStampImageParameters(Collections.singletonList(stampParams));
        
        SignatureImageParameters signatureParams = createImageParams();
        signatureParams.setPagePlacement(VisualSignaturePagePlacement.SINGLE_PAGE);
        signatureParams.setPage(-1);
        params.setSignatureImageParameters(signatureParams);
        
        DSSDocument document = new InMemoryDocument(byteArray);
        ToBeSigned toBeSigned = padesService.getDataToSign(document, params);
        SignatureValue signature = new SignatureValue();
        signature.setAlgorithm(SignatureAlgorithm.RSA_SHA512);
        
        byte[] signatureValue = signRemotely(toBeSigned.getBytes());
        signature.setValue(signatureValue);
        
        DSSDocument signed = padesService.signDocument(document, params, signature);
        IOUtils.copy(signed.openStream(), outputStream);
    }

    private byte[] signRemotely(byte[] bytes) {
        try {
            Channel channel = amqpConnection.createChannel();
            RpcClient rpcClient = new RpcClient(channel, rabbitMqExchange, rabbitMqRoutingKey);
            return rpcClient.primitiveCall(bytes);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
            
        }
        
    }

    private SignatureImageParameters createImageParams() {
        SignatureImageParameters imageParams = new SignatureImageParameters();
        imageParams.setImageDocument(new RemoteDocument(null, null, "Evrotrust_background.png"));
        imageParams.setxAxis(230);
        imageParams.setyAxis(-67);
        imageParams.setWidth(140);
        imageParams.setZoom(100);
        imageParams.setSignerTextImageVerticalAlignment(SignerTextImageVerticalAlignment.MIDDLE);
        imageParams.setTextParameters(new SignatureImageTextParameters());
        imageParams.getTextParameters().setSignerNamePosition(SignerPosition.FOREGROUND);
        imageParams.getTextParameters().setSignerTextHorizontalAlignment(SignerTextHorizontalAlignment.RIGHT);
        imageParams.getTextParameters().setRightPadding(4);
        imageParams.getTextParameters().setText("%CN_1%\n%CN_2%\n%CN_3%");
        imageParams.getTextParameters().setFont(new Font("helvetica", Font.PLAIN, 18));
        
        imageParams.setTextRightParameters(new SignatureImageTextParameters());
        imageParams.getTextRightParameters().setText("Digitally Signed with a\nQualified E-Seal.\nQualified Time-stamped.\n" + 
                "Date: %DateTimeWithTimeZone%\nCompliant with eIDAS.");
        imageParams.getTextRightParameters().setSignerNamePosition(SignerPosition.FOREGROUND);
        imageParams.getTextRightParameters().setSignerNamePosition(SignerPosition.LEFT);
        imageParams.getTextRightParameters().setFont(new Font("helvetica", Font.PLAIN, 12));
        imageParams.setDateFormat("dd.MM.yyyy HH:mm:ss XXX''");
        
        return imageParams;
    }
    
	@ModelAttribute("validationLevels")
	public ValidationLevel[] getValidationLevels() {
		return new ValidationLevel[] { ValidationLevel.BASIC_SIGNATURES, ValidationLevel.LONG_TERM_DATA, ValidationLevel.ARCHIVAL_DATA };
	}

}