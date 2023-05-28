from django.shortcuts import render
from store.models import Product
from django.http import HttpResponse
from django.core.mail import send_mail
def home(request):
    products = Product.objects.all().filter(is_available=True).order_by('created_date')

    context = {
        'products': products,
    }
    return render(request, 'home.html', context)

