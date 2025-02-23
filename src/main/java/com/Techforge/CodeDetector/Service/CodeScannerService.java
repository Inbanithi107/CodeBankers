package com.Techforge.CodeDetector.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.Techforge.CodeDetector.VulnerabilityRepository;
import com.Techforge.CodeDetector.DTO.Severity;
import com.Techforge.CodeDetector.Entity.Vulnerability;

@Service
public class CodeScannerService {
	
	@Autowired
	private VulnerabilityRepository repository;
	
	private String name = "inabnithi";
	
	public List<Vulnerability> scanCode(String filename, String code){
		
		List<Vulnerability> vulnerabilities = new ArrayList<>();
		
		Pattern pattern = Pattern.compile("password\\s*=\\s*\"[^\"]*\"", Pattern.CASE_INSENSITIVE);
		
		Matcher matcher = pattern.matcher(code);
		
		if(matcher.find()) {
			Vulnerability vulnerability = new Vulnerability();
			vulnerability.setFilename(filename);
			vulnerability.setIssueType("HardCoded data");
			vulnerability.setSeverity(Severity.HIGH.toString());
			vulnerability.setReccommendation("Remove hardcoded data and use environmentl variables");
			vulnerability.setDateTime(LocalDateTime.now());
			vulnerabilities.add(vulnerability);
		}
		
		return repository.saveAll(vulnerabilities);
		
	}

}
