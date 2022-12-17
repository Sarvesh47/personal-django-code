from .import views
from django.urls import path

from knox import views as knox_views
from .views import login_api, index, updateProfile,ChangePasswordView,requestPasswordResetEmail,passwordTokenCheckApi,setNewPassword


urlpatterns = [
    path('login', views.login_api),
    path('logout/', knox_views.LogoutView.as_view()),
    path('updateProfile', updateProfile.as_view()),
    path('view', index.as_view()),
    path('changepass', ChangePasswordView.as_view()),
    path('request_email', requestPasswordResetEmail.as_view(), name='request_email'),
    path('password_reset', passwordTokenCheckApi.as_view(), name='password_reset'),
    path('reset_complete', setNewPassword.as_view(), name='reset_complete'),


]