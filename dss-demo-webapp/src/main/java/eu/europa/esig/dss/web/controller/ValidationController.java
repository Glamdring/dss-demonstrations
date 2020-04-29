package eu.europa.esig.dss.web.controller;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.validation.Valid;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.SessionAttributes;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.executor.ValidationLevel;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.web.WebAppUtils;
import eu.europa.esig.dss.web.editor.EnumPropertyEditor;
import eu.europa.esig.dss.web.exception.SourceNotFoundException;
import eu.europa.esig.dss.web.model.ValidationForm;
import eu.europa.esig.dss.web.service.FOPService;
import eu.europa.esig.dss.ws.validation.common.ReportSigner;

@Controller
@SessionAttributes({ "simpleReportXml", "detailedReportXml", "diagnosticDataXml", "etsiValidationReport" })
@RequestMapping(value = "/validation")
public class ValidationController extends AbstractValidationController {

	private static final Logger LOG = LoggerFactory.getLogger(ValidationController.class);

	private static final String VALIDATION_TILE = "validation";
	private static final String VALIDATION_EMBED_TILE = "validation-embed";
	private static final String VALIDATION_RESULT_TILE = "validation_result";
	private static final String VALIDATION_RESULT_EMBED_TILE = "validation_result-embed";

	@Autowired
	private FOPService fopService;

	@Autowired
	private Resource defaultPolicy;

	@Autowired
    private ReportSigner reportSigner;
	
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
	
	/**
	 * A Restful endpoint that does the validation and provides a report as a response
	 */
	@RequestMapping(value = "/validate", method = RequestMethod.POST)
	@ResponseBody
    public ValidationDto validate(@RequestBody ValidationDto request) throws Exception {
	    byte[] document = Base64.getMimeDecoder().decode(request.getBase64bytes());
	    
	    SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(new InMemoryDocument(document));
        documentValidator.setCertificateVerifier(certificateVerifier);
        documentValidator.setValidationLevel(request.getValidationLevel());
        
        Reports reports = null;
        
        InputStream dpis = null;
        try {
            dpis = defaultPolicy.getInputStream();
            reports = documentValidator.validateDocument(dpis);
        } catch (IOException e) {
            LOG.error(e.getMessage(), e);
        } finally {
            Utils.closeQuietly(dpis);
        }
        
        String reportXml;
        if (request.getReportType() == ReportType.SIMPLE) {
            reportXml = reports.getXmlSimpleReport();
        } else if (request.getReportType() == ReportType.DETAILED){
            reportXml = reports.getXmlDetailedReport();
        } else if (request.getReportType() == ReportType.ETSI) {
            reportXml = reports.getXmlValidationReport();
        } else {
            throw new IllegalArgumentException("Unsupported report type " + request.getReportType());
        }
        
        try {
            ValidationDto response = new ValidationDto();
            ByteArrayOutputStream reportOut = new ByteArrayOutputStream();
            if (request.getReportType() == ReportType.ETSI) {
                reportSigner.signReportXml(reportXml, reportOut, request.getSessionId() != null ? request.getSessionId() : "");
                response.setXml(new String(reportOut.toByteArray(), StandardCharsets.UTF_8));
            } else {
                fopService.generateSimpleReport(reportXml, reportOut);
                ByteArrayOutputStream signedReportOut = new ByteArrayOutputStream();
                reportSigner.signReport(reportOut.toByteArray(), signedReportOut, request.getSessionId() != null ? request.getSessionId() : "");
                response.setBase64bytes(Base64.getEncoder().encodeToString(signedReportOut.toByteArray()));
            }
            
            response.setSessionId(request.getSessionId());
            response.setReportType(request.getReportType());
            response.setValidationLevel(request.getValidationLevel());
            return response;
        } catch (Exception ex) {
            LOG.error("An error occured while generating pdf for report : " + ex.getMessage(), ex);
            throw ex;
        }
        
	}
	
	@RequestMapping(method = RequestMethod.POST)
	public String validate(@ModelAttribute("validationForm") @Valid ValidationForm validationForm, BindingResult result, 
	        HttpSession session, Model model, HttpServletRequest request) {
		if (result.hasErrors()) {
			if (LOG.isDebugEnabled()) {
				List<ObjectError> allErrors = result.getAllErrors();
				for (ObjectError error : allErrors) {
					LOG.debug(error.getDefaultMessage());
				}
			}
			return VALIDATION_TILE;
		}

		SignedDocumentValidator documentValidator = SignedDocumentValidator
				.fromDocument(WebAppUtils.toDSSDocument(validationForm.getSignedFile()));

		CertificateVerifier cv = certificateVerifier;
		cv.setIncludeCertificateTokenValues(validationForm.isIncludeCertificateTokens());
		cv.setIncludeCertificateRevocationValues(validationForm.isIncludeRevocationTokens());
		cv.setIncludeTimestampTokenValues(validationForm.isIncludeTimestampTokens());
		documentValidator.setCertificateVerifier(cv);
		
		Locale locale = request.getLocale();
		LOG.trace("Requested locale : {}", locale);
		if (locale == null) {
			locale = Locale.getDefault();
			LOG.warn("The request locale is null! Use the default one : {}", locale);
		}
		documentValidator.setLocale(locale);

		List<DSSDocument> originalFiles = WebAppUtils.originalFilesToDSSDocuments(validationForm.getOriginalFiles());
		if (Utils.isCollectionNotEmpty(originalFiles)) {
			documentValidator.setDetachedContents(originalFiles);
		}
		documentValidator.setValidationLevel(validationForm.getValidationLevel());

		Reports reports = null;

		DSSDocument policyFile = WebAppUtils.toDSSDocument(validationForm.getPolicyFile());
		if (!validationForm.isDefaultPolicy() && (policyFile != null)) {
			try (InputStream is = policyFile.openStream()) {
				reports = documentValidator.validateDocument(is);
			} catch (IOException e) {
				LOG.error(e.getMessage(), e);
			}
		} else if (defaultPolicy != null) {
			try (InputStream is = defaultPolicy.getInputStream()) {
				reports = documentValidator.validateDocument(is);
			} catch (IOException e) {
				LOG.error("Unable to parse policy : " + e.getMessage(), e);
			}
		} else {
			LOG.error("Not correctly initialized");
		}

		// reports.print();

		setAttributesModels(model, reports);

		return VALIDATION_RESULT_TILE;
	}

	
	@RequestMapping(value = "/download-diagnostic-data")
    public void downloadDiagnosticData(HttpSession session, HttpServletResponse response) {
        String report = (String) session.getAttribute(XML_DIAGNOSTIC_DATA_ATTRIBUTE);

        response.setContentType(MimeType.XML.getMimeTypeString());
        response.setHeader("Content-Disposition", "attachment; filename=DSS-Diagnotic-data.xml");
        try {
            Utils.write(report.getBytes(StandardCharsets.UTF_8), response.getOutputStream());
        } catch (IOException e) {
            LOG.error("An error occured while outputing diagnostic data : " + e.getMessage(), e);
        }
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
    public String validateEmbed(@ModelAttribute("validationForm") @Valid ValidationForm validationForm, BindingResult result, HttpSession session, Model model, HttpServletRequest request) {
        if (result.hasErrors()) {
            return VALIDATION_RESULT_EMBED_TILE;
        }
        
        validate(validationForm, result, session, model, request);
        
        return VALIDATION_RESULT_EMBED_TILE;
    }

	@RequestMapping(value = "/download-simple-report")
	public void downloadSimpleReport(@RequestParam(value = "sign", required = false, defaultValue = "false") boolean sign,
	        HttpSession session, HttpServletResponse response) {
		try {
			String simpleReport = (String) session.getAttribute(XML_SIMPLE_REPORT_ATTRIBUTE);

			response.setContentType(MimeType.PDF.getMimeTypeString());
			response.setHeader("Content-Disposition", "attachment; filename=DSS-Simple-report.pdf");

			if (sign) {
			    ByteArrayOutputStream out = new ByteArrayOutputStream();
			    fopService.generateSimpleReport(simpleReport, out);
			    reportSigner.signReport(out.toByteArray(), response.getOutputStream(), session.getId());
			} else {
			    fopService.generateSimpleReport(simpleReport, response.getOutputStream());
			}
			
		} catch (Exception e) {
			LOG.error("An error occurred while generating pdf for simple report : " + e.getMessage(), e);
		}
	}

    @RequestMapping(value = "/download-detailed-report")
	public void downloadDetailedReport(@RequestParam(value = "sign", required = false, defaultValue = "false") boolean sign, 
	        HttpSession session, HttpServletResponse response) {
		try {
			String detailedReport = (String) session.getAttribute(XML_DETAILED_REPORT_ATTRIBUTE);

			response.setContentType(MimeType.PDF.getMimeTypeString());
			response.setHeader("Content-Disposition", "attachment; filename=DSS-Detailed-report.pdf");

			if (sign) {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                fopService.generateDetailedReport(detailedReport, out);
                reportSigner.signReport(out.toByteArray(), response.getOutputStream(), session.getId());
            } else {
                fopService.generateDetailedReport(detailedReport, response.getOutputStream());
            }
		} catch (Exception e) {
			LOG.error("An error occurred while generating pdf for detailed report : " + e.getMessage(), e);
		}
	}

    @RequestMapping(value = "/download-etsi-report")
    public void downloadETSIReport(@RequestParam(value = "sign", required = false, defaultValue = "false") boolean sign, 
            HttpSession session, HttpServletResponse response) {
        try {
            String etsiReport = (String) session.getAttribute(ETSI_VALIDATION_REPORT_ATTRIBUTE);

            response.setContentType(MimeType.XML.getMimeTypeString());
            response.setHeader("Content-Disposition", "attachment; filename=DSS-ETSI-Report.xml");

            if (sign) {
                reportSigner.signReportXml(etsiReport, response.getOutputStream(), session.getId());
            } else {
                response.getWriter().write(etsiReport);
            }
        } catch (Exception e) {
            LOG.error("An error occurred while signing XML for ETSI report : " + e.getMessage(), e);
        }
    }
    
	@RequestMapping(value = "/download-certificate")
	public void downloadCertificate(@RequestParam(value = "id") String id, HttpSession session, HttpServletResponse response) {
		DiagnosticData diagnosticData = getDiagnosticData(session);
        CertificateWrapper certificate = diagnosticData.getUsedCertificateById(id);
        if (certificate == null) {
            String message = "Certificate " + id + " not found";
            LOG.warn(message);
            throw new SourceNotFoundException(message);
        }
        String pemCert = DSSUtils.convertToPEM(DSSUtils.loadCertificate(certificate.getBinaries()));
        String filename = certificate.getReadableCertificateName().replace(" ", "_") + ".cer";
        
        addTokenToResponse(response, filename, MimeType.CER, pemCert.getBytes());
	}

	@RequestMapping(value = "/download-revocation")
	public void downloadRevocationData(@RequestParam(value = "id") String id, @RequestParam(value = "format") String format, HttpSession session,
			HttpServletResponse response) {
		DiagnosticData diagnosticData = getDiagnosticData(session);
        RevocationWrapper revocationData = diagnosticData.getRevocationById(id);
        if (revocationData == null) {
            String message = "Revocation data " + id + " not found";
            LOG.warn(message);
            throw new SourceNotFoundException(message);
        }
        String filename = revocationData.getId();
        MimeType mimeType;
        byte[] binaries;

        if (RevocationType.CRL.equals(revocationData.getRevocationType())) {
            mimeType = MimeType.CRL;
            filename += ".crl";

            if (Utils.areStringsEqualIgnoreCase(format, "pem")) {
                String pem = "-----BEGIN CRL-----\n";
                pem += Utils.toBase64(revocationData.getBinaries());
                pem += "\n-----END CRL-----";
                binaries = pem.getBytes();
            } else {
            	binaries = revocationData.getBinaries();
            }
        } else {
            mimeType = MimeType.BINARY;
            filename += ".ocsp";
            binaries = revocationData.getBinaries();
        }
        
        addTokenToResponse(response, filename, mimeType, binaries);
	}

	@RequestMapping(value = "/download-timestamp")
	public void downloadTimestamp(@RequestParam(value = "id") String id, @RequestParam(value = "format") String format, HttpSession session,
			HttpServletResponse response) {
		DiagnosticData diagnosticData = getDiagnosticData(session);
        TimestampWrapper timestamp = diagnosticData.getTimestampById(id);
        if (timestamp == null) {
            String message = "Timestamp " + id + " not found";
            LOG.warn(message);
            throw new SourceNotFoundException(message);
        }
        TimestampType type = timestamp.getType();
        
        byte[] binaries;
        if (Utils.areStringsEqualIgnoreCase(format, "pem")) {
            String pem = "-----BEGIN TIMESTAMP-----\n";
            pem += Utils.toBase64(timestamp.getBinaries());
            pem += "\n-----END TIMESTAMP-----";
            binaries = pem.getBytes();
        } else {
        	binaries = timestamp.getBinaries();
        }
        
        String filename = type.name() + ".tst";
        addTokenToResponse(response, filename, MimeType.TST, binaries);
	}

	public DiagnosticData getDiagnosticData(HttpSession session) {
		String diagnosticDataXml = (String) session.getAttribute(XML_DIAGNOSTIC_DATA_ATTRIBUTE);
		try {
			XmlDiagnosticData xmlDiagData = DiagnosticDataFacade.newFacade().unmarshall(diagnosticDataXml);
			return new DiagnosticData(xmlDiagData);
		} catch (Exception e) {
			LOG.error("An error occured while generating DiagnosticData from XML : " + e.getMessage(), e);
		}
		return null;
	}
    
    protected void addTokenToResponse(HttpServletResponse response, String filename, MimeType mimeType, byte[] binaries) {
    	response.setContentType(MimeType.TST.getMimeTypeString());
        response.setHeader("Content-Disposition", "attachment; filename=" + filename);
        try (InputStream is = new ByteArrayInputStream(binaries); OutputStream os = response.getOutputStream()) {
            Utils.copy(is, os);
        } catch (IOException e) {
            LOG.error("An error occurred while downloading a file : " + e.getMessage(), e);
        }
    }

	@ModelAttribute("validationLevels")
	public ValidationLevel[] getValidationLevels() {
		return new ValidationLevel[] { ValidationLevel.BASIC_SIGNATURES, ValidationLevel.LONG_TERM_DATA, ValidationLevel.ARCHIVAL_DATA };
	}
	
	@ModelAttribute("displayDownloadPdf")
	public boolean isDisplayDownloadPdf() {
		return true;
	}
	
	public static class ValidationDto {
	    private String base64bytes;
	    private String xml;
	    private ValidationLevel validationLevel = ValidationLevel.ARCHIVAL_DATA;
	    private ReportType reportType;
	    private String sessionId;

        public String getBase64bytes() {
            return base64bytes;
        }

        public void setBase64bytes(String base64bytes) {
            this.base64bytes = base64bytes;
        }

        public ReportType getReportType() {
            return reportType;
        }

        public void setReportType(ReportType reportType) {
            this.reportType = reportType;
        }

        public ValidationLevel getValidationLevel() {
            return validationLevel;
        }

        public void setValidationLevel(ValidationLevel validationLevel) {
            this.validationLevel = validationLevel;
        }

        public String getSessionId() {
            return sessionId;
        }

        public void setSessionId(String sessionId) {
            this.sessionId = sessionId;
        }

        public String getXml() {
            return xml;
        }

        public void setXml(String xml) {
            this.xml = xml;
        }
	}
	
	public static enum ReportType {
	    SIMPLE, DETAILED, ETSI
	}
}