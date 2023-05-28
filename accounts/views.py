from django.shortcuts import render,redirect
from .forms import RegistrationForm
from .models import Account
from django.contrib import messages, auth
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse

# veification emails
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMessage, send_mail
# Create your views here.
def register(requests):
    if requests.method == 'POST':
        form = RegistrationForm(requests.POST)
        if form.is_valid():
            first_name = form.cleaned_data['first_name']
            last_name = form.cleaned_data['last_name']
            phone_number = form.cleaned_data['phone_number']
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            username = email.split("@")[0]
            user = Account.objects.create_user(first_name=first_name, last_name=last_name, email=email, username=username,password=password )
            user.phone_number = phone_number
            user.save()
            current_site = get_current_site(requests)
            mail_subject = 'Please Activate Your Account'
            message = render_to_string('accounts/account_verification.html',{
                'user': user,
                'domain': current_site,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user)
            })

            to_email = email
            send_email = EmailMessage(mail_subject, message, to=[to_email])
            send_email.send()
            # messages.success(requests, 'Thank you for registring with us, we have sent you a varification email to you email address, please verify it')
            return redirect('/accounts/login/?command=verification&email='+email)

    else:
        form = RegistrationForm()
    context = {
        'form': form,
    }
    return render(requests, 'accounts/register.html', context)

def login(requests):
    if requests.method == 'POST':
        email = requests.POST['email']
        password = requests.POST['password']

        user = auth.authenticate(email=email, password=password)
        if user is not None:
            auth.login(requests, user)
            messages.success(requests, 'You are succesfully logged in ')
            return redirect('dashboard')
        else:
            messages.error(requests, 'invalid login credentials')
    return render(requests, 'accounts/login.html')

@login_required(login_url='login')
def logout(request):
    auth.logout(request)
    messages.success(request, 'You are logged out')
    return redirect('login')

def activate(requests, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Account._default_manager.get(pk=uid)
    except(TypeError,ValueError, OverflowError, Account.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(requests, 'Congratulation your account is activated')
        return redirect('login')
    else:
        messages.error(requests, 'Invalid activation link')
        return redirect('register')

@login_required(login_url='login')
def dashboard(requests):
    return render(requests,'accounts/dashbord.html')
