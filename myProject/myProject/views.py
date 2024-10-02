from django.shortcuts import render, redirect,HttpResponse
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from myApp.models import *
from django.core.mail import send_mail, BadHeaderError
from django.template.loader import render_to_string
from django.db.models.query_utils import Q
from django.utils.http import urlsafe_base64_encode
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.contrib.auth.forms import PasswordResetForm
from myProject.forms import *

from django.core.mail import send_mail, BadHeaderError
from django.template.loader import render_to_string
from django.db.models.query_utils import Q
from django.utils.http import urlsafe_base64_encode
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes


def signupPage(request):
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        confirm_password = request.POST['confirm-password']
        password = request.POST['password']
        confirm_password = request.POST['confirm-password']
        user_type = request.POST.get('user_type')

        if password == confirm_password:
            if Custom_User.objects.filter(username=username).exists():
                messages.error(request, 'Username already taken.')
                return redirect('signupPage')
            elif Custom_User.objects.filter(email=email).exists():
                messages.error(request, 'Email already registered.')
                return redirect('signupPage')
            else:
                user = Custom_User.objects.create_user(
                username=username,
                email=email,
                password=password,
                user_type=user_type,
                )
                user.save()
                return redirect("signInPage")
        else:
            messages.error(request, 'Passwords do not match.')
            return redirect('signupPage')

    return render(request, 'signupPage.html')

# Signin View
def signInPage(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']

        try:
            user = Custom_User.objects.get(email=email)
            user = authenticate(request, username=user.username, password=password)

            if user is not None:
                login(request, user)
                messages.success(request, f'Welcome, {user.username}!')
                return redirect('homePage') 
            else:
                messages.error(request, 'Invalid credentials, please try again.')
                return redirect('signInPage')

        except Custom_User.DoesNotExist:
            messages.error(request, 'No user with this email exists.')
            return redirect('signInPage')

    return render(request, 'signInPage.html')

# Signout View
def logoutPage(request):
    logout(request)
    messages.success(request, 'You have been logged out.')
    return redirect('signInPage')

@login_required
def homePage(request):
    
    return render(request,"homePage.html")

def password_reset_request(request):
    print("Password Reset")
    
    if request.method == "POST":
        
        print("Inside Password Reset and POST")
        
        password_reset_form = PasswordResetForm(request.POST)
        
        if password_reset_form.is_valid():
            data = password_reset_form.cleaned_data['email']
            
            associated_users = Custom_User.objects.filter(Q(email=data))
            
            if associated_users.exists():
                for user in associated_users: 
                    subject = "Password Reset Requested"
                    email_template_name = "password/password_reset_email.txt"
                    c = {
                        "email": user.email,  
                        'domain': '127.0.0.1:8000',
                        'site_name': 'Website',
                        "uid": urlsafe_base64_encode(force_bytes(user.pk)),
                        "user": user,
                        'token': default_token_generator.make_token(user),
                        'protocol': 'http',
                    }
                    email = render_to_string(email_template_name, c)
                    try:
                        send_mail(subject, email, 'rajeshcpi788@gmail.com', [user.email], fail_silently=False)
                    except BadHeaderError:
                        return HttpResponse('Invalid header found.')
                
                return redirect("password_reset_done") 
    else:
        password_reset_form = PasswordResetForm()

    return render(request, "password/password_reset.html", {"password_reset_form": password_reset_form})
