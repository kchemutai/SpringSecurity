package miu.edu.SpringSecurity.config;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import miu.edu.SpringSecurity.user.repository.UserRepository;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Configuration
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //verify that the request has an authorization header
       String header= request.getHeader("Authorization");
       if(header!=null && header.startsWith("Bearer ")) {
           String token = header.substring(7);
           Claims claims = jwtService.getClaimsFromToken(token);
           String username = claims.getSubject();
//           if(username!=null && SecurityContextHolder.getContext().getAuthentication() == null) {
           if(username!=null ) {
               //check if user exists in DB
               var user = userRepository.findByEmail(username).orElseThrow(()->new UsernameNotFoundException("User not found"));

               //create the username and password authentication
               UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                       user,
                       null,
                       user.getAuthorities());
               SecurityContextHolder.getContext().setAuthentication(authenticationToken);
           }
       }
        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return request.getServletPath().contains("/api/v1/auth");
    }
}
