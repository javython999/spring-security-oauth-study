package com.errday.oauth2resourceserver.controller;

import com.errday.oauth2resourceserver.dto.PhotoDto;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PhotoController {

    @GetMapping("/photos/1")
    public PhotoDto photo1() {
        return PhotoDto.builder()
                .photoId("1")
                .photoTitle("photo 1 title")
                .photoDescription("photo 1 description")
                .build();
    }

    @GetMapping("/photos/2")
    @PreAuthorize("hasAnyAuthority('SCOPE_photo')")
    public PhotoDto photo2() {
        return PhotoDto.builder()
                .photoId("2")
                .photoTitle("photo 2 title")
                .photoDescription("photo 2 description")
                .build();
    }

    @GetMapping("/photos/3")
    public PhotoDto photo3() {
        return PhotoDto.builder()
                .photoId("3")
                .photoTitle("photo 3 title")
                .photoDescription("photo 3 description")
                .build();
    }
}
