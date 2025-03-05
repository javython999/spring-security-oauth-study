package com.errday.resourceserver;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@Slf4j
@RestController
public class PhotoController {

    @GetMapping("/photos")
    public List<Photo> photos(){

        Photo photo1 = Photo.of("1 ", "Photo1 title ", "Photo is nice ", "user1 ");
        Photo photo2 = Photo.of("2 ", "Photo2 title ", "Photo is beautiful ", "user2 ");

        return List.of(photo1, photo2);
    }

    @GetMapping("/remote-photos")
    public List<Photo> remotePhotos(){

        Photo photo1 = Photo.of("1 ", "Photo1 title ", "Photo is nice ", "user1 ");
        Photo photo2 = Photo.of("2 ", "Photo2 title ", "Photo is beautiful ", "user2 ");

        return List.of(photo1, photo2);
    }


}