package com.shalunov.cvGenerator.presentation;

import java.util.HashSet;
import java.util.Set;

import javax.validation.Valid;

import com.shalunov.cvGenerator.application.WebSecurity.JwtProvider;
import com.shalunov.cvGenerator.application.WebSecurity.JwtResponse;
import com.shalunov.cvGenerator.domain.LoginForm;
import com.shalunov.cvGenerator.domain.Role;
import com.shalunov.cvGenerator.domain.SignUpForm;
import com.shalunov.cvGenerator.domain.User;
import com.shalunov.cvGenerator.domain.enums.RolesEnum;
import com.shalunov.cvGenerator.infrastructure.repositories.RoleRepository;
import com.shalunov.cvGenerator.infrastructure.repositories.UserRepository;
import org.apache.commons.logging.Log;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.view.RedirectView;

@RestController
@RequestMapping("/api/auth")
public class AuthRestAPIs {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtProvider jwtProvider;

    @GetMapping(value = {"/signin",})
    public ModelAndView authenticateUserView(Model model) {
        ModelAndView modelAndView = new ModelAndView();
        LoginForm loginForm = new LoginForm();
        model.addAttribute("loginForm", loginForm);
        modelAndView.setViewName("login");
        return modelAndView;
    }

    @PostMapping("/signin")
    public ResponseEntity authenticateUser(@Valid @RequestBody LoginForm loginForm) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginForm.getUsername(),
                        loginForm.getPassword()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String jwt = jwtProvider.generateJwtToken(authentication);
        return ResponseEntity.ok(new JwtResponse(jwt));
    }

    @GetMapping(value = {"/signup",})
    public ModelAndView registerUserView(Model model) {
        ModelAndView modelAndView = new ModelAndView();
        SignUpForm signUpForm = new SignUpForm();
        model.addAttribute("signUpForm", signUpForm);
        modelAndView.setViewName("registration");
        return modelAndView;
    }

    @PostMapping("/signup")
    public RedirectView  registerUser(@Valid SignUpForm signUpRequest, RedirectAttributes redirectAttrs) {
        ModelAndView modelAndView = new ModelAndView();
        if(userRepository.existsByUsername(signUpRequest.getUsername())) {
            redirectAttrs.addAttribute("errorMessage", "Username is already taken!");
            return new RedirectView("error");
        }

        if(userRepository.existsByEmail(signUpRequest.getEmail())) {
            redirectAttrs.addAttribute("errorMessage", "Email is already in use!");
            return new RedirectView("error");
        }
        // Creating user's account
        User user = new User(signUpRequest.getName(), signUpRequest.getUsername(),
                signUpRequest.getEmail(), encoder.encode(signUpRequest.getPassword()));

        Set strRoles = signUpRequest.getRole();
        Set roles = new HashSet<>();
        if(strRoles == null) {
            strRoles = new HashSet<>();
        }

        strRoles.forEach(role -> {
            if ("admin".equals(role)) {
                Role adminRole = roleRepository.findByName(RolesEnum.ROLE_ADMIN)
                        .orElseThrow(() -> new RuntimeException("Fail! -> Cause: User Role not find."));
                roles.add(adminRole);
            } else if ("pm".equals(role)) {
                Role pmRole = roleRepository.findByName(RolesEnum.ROLE_PM)
                        .orElseThrow(() -> new RuntimeException("Fail! -> Cause: User Role not find."));
                roles.add(pmRole);
            } else {
                Role userRole = roleRepository.findByName(RolesEnum.ROLE_USER)
                        .orElseThrow(() -> new RuntimeException("Fail! -> Cause: User Role not find."));
                roles.add(userRole);
            }
        });

        user.setRoles(roles);
        userRepository.save(user);

        return new RedirectView("redirect");
    }


    @GetMapping(value = {"/api/auth/redirect",})
    public ModelAndView refirectToLoginView(Model model) {
        ModelAndView modelAndView = new ModelAndView();
        modelAndView.setViewName("registerSuccessful");
        return modelAndView;
    }
}
