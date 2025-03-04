package com.errday.oauth2resourceserver.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class PhotoDto {

    private String userid;
    private String photoId;
    private String photoTitle;
    private String photoDescription;
}
