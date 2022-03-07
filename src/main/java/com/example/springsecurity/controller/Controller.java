package com.example.springsecurity.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
public class Controller {

    @GetMapping("/message")
    public String helloUser(){
        return "Hello User :) ";
    }

    @GetMapping("/details")
    public String getDocument(){
        return "Documents";
    }

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @PostMapping("/post")
    public String sendSms(@RequestBody String message){
        return "sms: "+message+" successfully sent";
    }

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @PutMapping("/update")
    public String updateSms(@RequestBody String message){
        return "sms: "+message+" succesfully updated";
    }

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @DeleteMapping("/delete/{id}")
    public String deleteMessage(@PathVariable Long id){
        return "message successfully deleted: "+id;
    }


}
