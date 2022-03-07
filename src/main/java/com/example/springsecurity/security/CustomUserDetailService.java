package com.example.springsecurity.security;

import com.example.springsecurity.data.entity.Role;
import com.example.springsecurity.data.entity.User;
import com.example.springsecurity.data.repository.UserRepository;
import com.example.springsecurity.resource.UserDetail;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.stream.Collectors;
import static com.example.springsecurity.enums.ErrorCase.USER_NOT_FOUND;
@Service
@RequiredArgsConstructor
public class CustomUserDetailService implements UserDetailsService {
    private final UserRepository userRepository;


    @Override
    public UserDetails loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {
        User user = userRepository.findByUsernameOrEmail(usernameOrEmail, usernameOrEmail)
                .orElseThrow(() -> new UsernameNotFoundException(USER_NOT_FOUND.getMessage()));
//        if(user==null){   //enums instead of this
//            throw new UsernameNotFoundException(usernameOrEmail);
//        }
        return new UserDetail(user.getUsername(), user.getPassword(), mapToGrantedAuthority(user.getRoles()));
//      //      return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), mapToGrantedAuthority(user.getRoles()));
        //bele gorsenmesin deyene ve interfacenin obyektini yaradib return ede bilmediyimiz ucun UserDetails interfacesinden implements eden User calssini extend edeb bir class yaradib yaziriq
    }



    private Set<GrantedAuthority> mapToGrantedAuthority(Set<Role> roles) {
        return roles.stream().map(role -> new SimpleGrantedAuthority(role.getName())).collect(Collectors.toSet());
    }
}
