package com.errday.resourceserver;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class Photo {

    private String photoId;
    private String photoTitle;
    private String photoDescription;
    private String userId;

    public static Photo of(String photoId, String photoTitle, String photoDescription, String userId) {
        return Photo.builder()
                .photoId(photoId)
                .photoTitle(photoTitle)
                .photoDescription(photoDescription)
                .userId(userId)
                .build();
    }
}
