#include "models.h"
#include <string.h>

const char* role_to_string(UserRole role)
{
    switch (role) {
        case ROLE_CUSTOMER: return "CUSTOMER";
        case ROLE_EMPLOYEE: return "EMPLOYEE";
        case ROLE_MANAGER:  return "MANAGER";
        case ROLE_ADMIN:    return "ADMIN";
        default:            return "UNKNOWN";
    }
}

UserRole string_to_role(const char *str)
{
    if (strcasecmp(str, "CUSTOMER") == 0) return ROLE_CUSTOMER;
    if (strcasecmp(str, "EMPLOYEE") == 0) return ROLE_EMPLOYEE;
    if (strcasecmp(str, "MANAGER") == 0)  return ROLE_MANAGER;
    if (strcasecmp(str, "ADMIN") == 0)    return ROLE_ADMIN;
    return ROLE_UNKNOWN;
}
