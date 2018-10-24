package com.baeldung.springsecuritythymeleaf;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.context.annotation.SessionScope;

@Controller
@SessionScope
public class ViewController {

    private String data;

    @GetMapping("/")
    public String home1() {
        return "/home";
    }

    @GetMapping("/home")
    public String home() {
        return "/home";
    }

    @GetMapping("/admin")
    public String admin() {
        return "/admin";
    }

    @GetMapping("/user")
    public String user(Model model) {
        data = "ABC";
        model.addAttribute("test", data);
        return "/user";
    }

    @GetMapping("/test")
    public String test(Model model) {
        model.addAttribute("test", data);
        return "/test";
    }

    @GetMapping("/about")
    public String about() {
        return "/about";
    }

    @GetMapping("/login")
    public String login() {
        return "/login";
    }

    @GetMapping("/403")
    public String error403() {
        return "/error/403";
    }

//
//    @RequestMapping({ "/index", "/" })
//    public String index() {
//        return "index";
//    }
}
