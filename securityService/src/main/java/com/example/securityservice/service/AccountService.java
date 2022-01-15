package com.example.securityservice.service;

import com.example.securityservice.entity.AppRole;
import com.example.securityservice.entity.AppUser;
import java.util.List;

public interface AccountService {
    AppUser addNewUser(AppUser appUser);
    AppRole addNewRole(AppRole appRole);
    void addRoleToUser(String username,String roleName);
    AppUser loadUserByUsername(String username);
    List<AppUser> listUsers();
}
