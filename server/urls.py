
from django.contrib import admin
from django.urls import path, re_path
from . import views

urlpatterns = [
    path('admin/', admin.site.urls),
    re_path('login', views.login),
    re_path('send', views.sending),
    re_path('signup', views.signup),
    re_path('test_token', views.test_token),
    re_path('logout', views.logout),
    path('forgot_password', views.forgotPassword,name="request-password-reset",),
    path('password-reset/<str:encoded_pk>/<str:token>/', views.reset, name='reset-password')
]
