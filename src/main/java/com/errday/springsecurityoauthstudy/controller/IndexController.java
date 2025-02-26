package com.errday.springsecurityoauthstudy.controller;

import com.errday.springsecurityoauthstudy.model.PrincipalUser;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@RequiredArgsConstructor
public class IndexController {

    @GetMapping("/")
    public String index(Model model, Authentication authentication, @AuthenticationPrincipal PrincipalUser principalUser) {

        if (authentication != null) {
            model.addAttribute("user", principalUser.providerUser().getUsername());
            model.addAttribute("provider", principalUser.providerUser().getProvider());
        }
        return "index";
    }
}
