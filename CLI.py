#!/usr/bin/python3
import csv, os, subprocess, sys, time, matplotlib, pandas, threading, click

import pandas as pd
import numpy as np
#import matplotlib.pyplot as plt

from multiprocessing.dummy import Pool

from cyberscope import www_driver, mx_driver, read_results


@click.group(invoke_without_command=True)
@click.option(
	'--infile', '-in',
	type=click.Path(),
	default='top-1m.csv',
)
@click.option(
	'--outfile', '-out', 
	type=str, 
	default="yahoo.csv"
)

@click.pass_context
def main(ctx, infile, outfile):
	if(ctx.invoked_subcommand is None):
		click.clear()
		click.echo(click.style('##########################', fg='green'))
		click.echo(click.style('##  Cyberscope Project  ##', fg='green'))
		click.echo(click.style('##########################\n', fg='green'))
		click.echo('')

	ctx.obj = {
		'infile': infile,
		'outfile': outfile
	}

@main.command()
@click.option('--r', nargs=1, default=10, show_default=True, type=int, help='range of lines to analyze')

@click.pass_context
def run(ctx, r):

	d_list = []
	with open(ctx.obj['infile']) as f:
		reader = csv.reader(f, delimiter=',')
		line = 0;
		click.echo('Performing scan for %s...\n' % ctx.obj['infile'])

		for row in reader:
			line+=1
			if(line==r):
				break;
			elif(line >= 0):
				d_list.append(row[1])

	start = time.time()
	with click.progressbar(d_list, length=len(d_list)) as bar:

	## multithreading mx analysis
#		tlist_mx = []
#		for d in bar:
#			thread = threading.Thread(target=mx_driver, args=(d,))
#			tlist_mx.append(thread)
#			thread.start()

#		for thread in tlist_mx:
#			thread.join()

	## multithreading web analysis
#		tlist_www = []
#		for d in bar:
#		    thread = threading.Thread(target=www_driver, args=(d,))
#		    tlist_www.append(thread)
#		    thread.start()

#		for thread in tlist_www:
#		    thread.join()

	## without multithreading
		count = 0
		for domain in bar:
			count+=1
			mx_driver(domain)


	## time data 
	end = time.time()
	t_total = end - start
	click.echo('total Time: %s' % t_total)

#@main.command()
#@click.option('--type', '-t', type=click.Choice(['mx', 'web']), help='remove a file. Can specify with \'mx\' or \'web\'')
#@click.pass_context
#def rm(ctx, t):
#	if(rm == "web"):
#		subprocess.Popen(['rm tls_results.csv'], stdout=subprocess.PIPE, shell=True)
#	elif(rm == ""):
#		subprocess.Popen(['rm host_results.csv'], stdout=subprocess.PIPE, shell=True)


@main.command()
@click.option('--ran', '-r', nargs=1, default=10, type=int, help='range of lines to analyze')
@click.option('--domain', '-d', nargs=1, default=["all",], show_default=True, multiple=True, type=str, help='include specified domains')
@click.option('--exclude', '-ex', nargs=1, multiple=True, type=str, help='exclude specified domains')
@click.option('--find', '-f', nargs=1, multiple=True, type=str, help='search data for specified text')
@click.option('--sort', nargs=1, default="Domain", show_default=False, type=str, help='sort specified column in descending order')
@click.pass_context
def read(ctx, ran, exclude, domain, find, port):
	read_results(ctx.obj['outfile'], exclude, domain, ran, port, sort)

@main.command()
@click.pass_context
def graph(ctx):
	pass
#	%matplotlib inline
#	results=pd.read_csv("output.csv")
#	results.head()
#	results.describe


#	my_plot = sales_totals.plot(kind='bar')


if __name__ == '__main__':
    main(obj={})
