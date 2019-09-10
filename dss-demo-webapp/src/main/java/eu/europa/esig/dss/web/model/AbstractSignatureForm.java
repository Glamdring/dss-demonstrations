package eu.europa.esig.dss.web.model;

import java.util.Date;
import java.util.List;

import javax.validation.constraints.NotNull;

import org.springframework.web.multipart.MultipartFile;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SignatureLevel;


public abstract class AbstractSignatureForm {

	// @AssertTrue(message = "{error.nexu.not.found}")
	private boolean nexuDetected;

	private Date signingDate;

	private boolean signWithExpiredCertificate;

	private boolean addContentTimestamp;

	@NotNull(message = "{error.signature.form.mandatory}")
	private SignatureForm signatureForm;

	@NotNull(message = "{error.signature.level.mandatory}")
	private SignatureLevel signatureLevel;

	@NotNull(message = "{error.digest.algo.mandatory}")
	private DigestAlgorithm digestAlgorithm;

	private String base64Certificate;

	private List<String> base64CertificateChain;

	private EncryptionAlgorithm encryptionAlgorithm;

	private String base64SignatureValue;

	private String stampImagePages;
	
	private String signatureImagePage;
	
	private MultipartFile signatureImage;
	
	private String signatureImageXml;
	
	private String stampImageXml;
	
	private TimestampDTO contentTimestamp;

	public boolean isNexuDetected() {
		return nexuDetected;
	}

	public void setNexuDetected(boolean nexuDetected) {
		this.nexuDetected = nexuDetected;
	}

	public Date getSigningDate() {
		return signingDate;
	}

	public void setSigningDate(Date signingDate) {
		this.signingDate = signingDate;
	}

	public boolean isSignWithExpiredCertificate() {
		return signWithExpiredCertificate;
	}

	public void setSignWithExpiredCertificate(boolean signWithExpiredCertificate) {
		this.signWithExpiredCertificate = signWithExpiredCertificate;
	}

	public boolean isAddContentTimestamp() {
		return addContentTimestamp;
	}

	public void setAddContentTimestamp(boolean addContentTimestamp) {
		this.addContentTimestamp = addContentTimestamp;
	}

	public SignatureForm getSignatureForm() {
		return signatureForm;
	}

	public void setSignatureForm(SignatureForm signatureForm) {
		this.signatureForm = signatureForm;
	}

	public SignatureLevel getSignatureLevel() {
		return signatureLevel;
	}

	public void setSignatureLevel(SignatureLevel signatureLevel) {
		this.signatureLevel = signatureLevel;
	}

	public DigestAlgorithm getDigestAlgorithm() {
		return digestAlgorithm;
	}

	public void setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
		this.digestAlgorithm = digestAlgorithm;
	}

	public String getBase64Certificate() {
		return base64Certificate;
	}

	public void setBase64Certificate(String base64Certificate) {
		this.base64Certificate = base64Certificate;
	}

	public List<String> getBase64CertificateChain() {
		return base64CertificateChain;
	}

	public void setBase64CertificateChain(List<String> base64CertificateChain) {
		this.base64CertificateChain = base64CertificateChain;
	}

	public EncryptionAlgorithm getEncryptionAlgorithm() {
		return encryptionAlgorithm;
	}

	public void setEncryptionAlgorithm(EncryptionAlgorithm encryptionAlgorithm) {
		this.encryptionAlgorithm = encryptionAlgorithm;
	}

	public String getBase64SignatureValue() {
		return base64SignatureValue;
	}

	public void setBase64SignatureValue(String base64SignatureValue) {
		this.base64SignatureValue = base64SignatureValue;
	}
	
	public String getStampImagePages() {
		return stampImagePages;
	}

	public void setStampImagePages(String stampImagePages) {
		this.stampImagePages = stampImagePages;
	}

	public String getSignatureImagePage() {
		return signatureImagePage;
	}

	public void setSignatureImagePage(String signatureImagePage) {
		this.signatureImagePage = signatureImagePage;
	}

	public MultipartFile getSignatureImage() {
		return signatureImage;
	}

	public void setSignatureImage(MultipartFile signatureImage) {
		this.signatureImage = signatureImage;
	}

    public String getSignatureImageXml() {
        return signatureImageXml;
    }

    public void setSignatureImageXml(String signatureImageXml) {
        this.signatureImageXml = signatureImageXml;
    }

    public String getStampImageXml() {
        return stampImageXml;
    }

    public void setStampImageXml(String stampImageXml) {
        this.stampImageXml = stampImageXml;
    }
	public TimestampDTO getContentTimestamp() {
		return contentTimestamp;
	}

	public void setContentTimestamp(TimestampDTO contentTimestamp) {
		this.contentTimestamp = contentTimestamp;
	}

}
