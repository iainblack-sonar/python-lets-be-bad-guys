from django.urls import re_path
from django.views.generic.base import TemplateView
from django.contrib.staticfiles.urls import staticfiles_urlpatterns


# Uncomment the next two lines to enable the admin:
# from django.contrib import admin
# admin.autodiscover()

urlpatterns = [
    re_path(r'^$', TemplateView.as_view(template_name='index.html'), name="home"),
    re_path(r'^about$',
        TemplateView.as_view(template_name='about.html'), name="about"),
    re_path(r'^conclusion$',
        TemplateView.as_view(template_name='conclusion.html'),
        name="conclusion"),
]


import badguys.vulnerable.views as exercises

urlpatterns += [

    # Exercise 01 - Injection Attacks
    re_path(r'^injection$',
        TemplateView.as_view(template_name='vulnerable/injection/index.html'),
        name="injection"),
    re_path(r'^injection/sql$', exercises.sql, name="injection-sql"),
    re_path(r'^injection/file-access$', exercises.file_access,
        name="injection-file-access"),
    re_path(r'^user-pic$', exercises.user_pic, name='user-pic'),
    re_path(r'^injection/code-execution$', exercises.code_execution,
        name="injection-code-execution"),
    re_path(r'^injection/command$', exercises.command_injection,
        name="injection-command"),
    re_path(r'^injection/deserialization$', exercises.insecure_deserialization,
        name="injection-deserialization"),

    # Exercise 02 - Broken Authentication & Session Management
    re_path(r'^broken-auth-and-session-management$',
        TemplateView.as_view(template_name='vulnerable/broken_auth/index.html'),
        name='broken-auth'),

    # Exercise 03 - XSS Attacks
    re_path(r'^cross-site-scripting$',
        TemplateView.as_view(template_name='vulnerable/xss/index.html'),
        name="xss"),
    re_path(r'^cross-site-scripting/path-matching/(?P<path>.+)$',
        exercises.xss_path, name="xss-path"),
    re_path(r'^cross-site-scripting/form-field$', exercises.xss_form,
        name="xss-form"),
    re_path(r'^cross-site-scripting/query-params$', exercises.xss_query,
        name="xss-query"),

    # Exercise 04 - Insecure Direct Object References
    re_path(r'^direct-object-references$',
        TemplateView.as_view(template_name='vulnerable/direct_object_references/index.html'),
        name="direct-object-references"),

    re_path(r'^direct-object-references/users/(?P<userid>\d+)$',
        exercises.dor_user_profile, name='direct-object-references-profile'),

    # Exercise 05 - Security Misconfiguration
    re_path(r'^misconfiguration$',
        TemplateView.as_view(template_name='vulnerable/misconfig/index.html'),
        name='misconfig'),

    re_path(r'^misconfiguration/boom$', exercises.boom, name='misconfig-boom'),

    # Exercise 06 - Sensitive Data Exposure
    re_path(r'^data-exposure$',
        TemplateView.as_view(template_name='vulnerable/exposure/index.html'),
        name='exposure'),
    re_path(r'^data-exposure/login$', exercises.exposure_login,
        name='exposure-login'),

    # Exercise 07 - Missing Function-Level Access Control

    re_path(r'^missing-access-control$',
        TemplateView.as_view(template_name='vulnerable/access_control/index.html'),
        name='access-control'),

    re_path(r'^missing-access-control/happy-page$',
        exercises.missing_access_control, name='access-control-missing'),

    # Exercise 08 - CSRF Attacks
    re_path(r'^csrf$',
        TemplateView.as_view(template_name='vulnerable/csrf/index.html'),
        name='csrf'),
    re_path(r'^csrf/image$', exercises.csrf_image, name='csrf-image'),
    re_path(r'^csrf/third-party-site$',
        TemplateView.as_view(template_name='vulnerable/csrf/third_party.html'),
        name='csrf-third-party'),
    re_path(r'^csrf/gift-card$',
        TemplateView.as_view(template_name='vulnerable/csrf/gift_card.html'),
        name='csrf-gift-card'),

    # Exercise 09 - Using Known Vulnerable Components
    re_path(r'^vulnerable-components$',
        TemplateView.as_view(template_name='vulnerable/components/index.html'),
        name='components'),

    # Exercise 10 - Unvalidated Redirects & Forwards
    re_path(r'^redirects-and-forwards$',
        TemplateView.as_view(template_name='vulnerable/redirects/index.html'),
        name='redirects'),
    re_path(r'^redirects-and-forwards/redirects$',
        TemplateView.as_view(template_name='vulnerable/redirects/redirects.html'),
        name='redirects-redirects'),
    re_path(r'^redirects-and-forwards/redirect$', exercises.unvalidated_redirect,
        name='redirects-redirect'),
    re_path(r'^redirects-and-forwards/forwards$',
        TemplateView.as_view(template_name='vulnerable/redirects/forwards.html'),
        name='redirects-forwards'),
    re_path(r'^redirects-and-forwards/forward$', exercises.unvalidated_forward,
        name='redirects-forward')

    # Uncomment the admin/doc line below to enable admin documentation:
    # re_path(r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    # re_path(r'^admin/', include(admin.site.urls)),
]

urlpatterns += staticfiles_urlpatterns()
