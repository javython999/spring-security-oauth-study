package com.errday.springsecurityoauthstudy.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@RequiredArgsConstructor
public class HomeController {

    @GetMapping("/home")
    public String home(Authentication authentication, Model model) {
        model.addAttribute("oAuth2AuthenticationToken", authentication);
        return "home";
    }
}
