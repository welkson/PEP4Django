from django.http import HttpResponse
from django.shortcuts import render
from django.contrib.auth.decorators import login_required


@login_required
def index(request):
    return render(request, 'index.html', {})

@login_required
def new_ticket(request):
    return render(request, 'new_ticket.html', {})

@login_required
def list_tickets(request):
    return render(request, 'list_tickets.html', {})
