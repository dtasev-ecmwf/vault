#!/usr/bin/env python3
from ecmwf_vault import value

secret = value("user_applications_and_services_team/cems_web",
               field="k8s-cems-test")     # a Secret, not a str
password = secret.reveal()           # the explicit step; everything else refuses

print(f"got {len(password)} characters")   # f"{secret}" would print "<Secret>"
