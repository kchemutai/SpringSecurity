package miu.edu.SpringSecurity.secure;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/management")
public class MemberController {

    @GetMapping
    public String getMember() {
        return "Member";
    }

    @GetMapping("/member-read-only")
    @PreAuthorize("hasAnyAuthority('member:read')")
    public String getMemberReadOnly() {
        return "MemberReadOnly";
    }
}
