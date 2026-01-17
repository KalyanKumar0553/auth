package com.src.main.auth.controller;

import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SwaggerUiCustomController {

	@GetMapping(value = "/swagger-ui-custom.html", produces = MediaType.TEXT_HTML_VALUE)
	public ResponseEntity<Resource> swaggerUiCustom() {
		return ResponseEntity.ok(new ClassPathResource("static/swagger-ui-custom.html"));
	}
}
