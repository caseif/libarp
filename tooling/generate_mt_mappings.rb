#!/usr/bin/env ruby

require 'csv'
require 'fileutils'

USER_MAPPINGS_PATH = "./res/user_mappings.csv"
ARP_MAPPINGS_PATH = "./res/arp_mappings.csv"
APACHE_MAPPINGS_PATH = "./res/mime.types"

OUTPUT_DIR = "./output/"
OUTPUT_PATH = "./output/full_mappings.csv"

APACHE_COMMENT_CHAR = '#'

def parse_csv(path)
    csv = CSV.read path
    csv.reduce({}) { |hash, row| {row[0] || "" => row[1]}.merge(hash) }
end

def parse_apache(path)
    f = File.open(path, 'r')

    mappings = {}

    f.each_line { |line|
        next if line.start_with? APACHE_COMMENT_CHAR or line.empty?

        spl = line.split(/\t+/)
        mt = spl[0]
        exts = spl[1].split(/ +/)

        exts.each { |ext|
            mappings[ext.strip || ""] = mt
        }
    }

    mappings
end

def process_input()
    unless File.file? APACHE_MAPPINGS_PATH
        puts "Apache mappings file (mime.types) is missing"
        exit
    end
    unless File.file? ARP_MAPPINGS_PATH
        puts "ARP mappings file (arp_mappings.csv) is missing"
        exit
    end

    mappings = {}

    # order is important here, highest-precedence mappings go in first

    if File.file? USER_MAPPINGS_PATH
        user_mappings = parse_csv USER_MAPPINGS_PATH
        mappings = user_mappings.merge mappings
    end

    arp_mappings = parse_csv ARP_MAPPINGS_PATH
    mappings = arp_mappings.merge mappings

    apache_mappings = parse_apache APACHE_MAPPINGS_PATH
    mappings = apache_mappings.merge mappings
end

def generate_output(mappings)
    FileUtils.mkdir_p OUTPUT_DIR
    f = File.open(OUTPUT_PATH, "w+")
    mappings.keys.sort.each { |key|
        f.puts("#{key.downcase},#{mappings[key].downcase}")
    }
end

def consolidate_mappings()
    mappings = process_input()
    generate_output(mappings)
    puts "Success, output written to #{OUTPUT_PATH}"
end

consolidate_mappings()
