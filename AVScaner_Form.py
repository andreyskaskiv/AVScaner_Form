import asyncio
import os
import random
import urllib.parse as urlparse
from asyncio import Queue
from concurrent.futures import ThreadPoolExecutor

import aiohttp
import chardet
from bs4 import BeautifulSoup

from handlers.file_handler import (read_file_to_queue,
                                   read_file_to_list,
                                   write_to_file,
                                   load_patterns,
                                   writing_to_file_of_successful_payload)
from handlers.parse_arguments import parse_arguments
from handlers.user_agent import USER_AGENTS
from handlers.utils import C, timer_decorator, limit_rate_decorator

PARSE_ARGS = parse_arguments()

INPUT = PARSE_ARGS.input
OUTPUT = PARSE_ARGS.output
PAYLOADS = PARSE_ARGS.payloads
ANSWERS = PARSE_ARGS.answers
CALL_LIMIT_PER_SECOND = PARSE_ARGS.concurrency
TIMEOUT = PARSE_ARGS.timeout
VERBOSE = PARSE_ARGS.verbose
VERBOSE_REQUESTS = PARSE_ARGS.verbose_requests
POST_METHOD = PARSE_ARGS.post
PROXY = PARSE_ARGS.proxy

@limit_rate_decorator(calls_limit=CALL_LIMIT_PER_SECOND, timeout=1)
async def make_request(url, session):
    proxy_url = PROXY if PROXY else None
    user_agent = random.choice(USER_AGENTS)
    headers = {'User-Agent': user_agent}

    scheme = url.replace('https://', 'http://')

    try:
        async with session.get(scheme, headers=headers, proxy=proxy_url, ssl=False) as response:
            try:
                raw_data = await response.read()
                detected_encoding = chardet.detect(raw_data)['encoding']
                html = raw_data.decode(detected_encoding,
                                       errors="ignore")
                return url, response.status, html

            except aiohttp.ClientPayloadError as e:
                print(f'{C.yellow}\n[!] Warning in make_request for {url}: {e}. Some data may be missing.{C.norm}')
                return url, response.status, None

    except aiohttp.ClientError as e:
        print(f'{C.red}[!] HTTP Client Error in make_request for {url}: {e}{C.norm}')
        return url, None, None

    except Exception as e:
        print(f'{C.red}[!] Unexpected Error in make_request for {url}: {e}{C.norm}')
        return url, None, None


@limit_rate_decorator(calls_limit=CALL_LIMIT_PER_SECOND, timeout=1)
async def submit_form(method, post_url, form, post_data, session):
    user_agent = random.choice(USER_AGENTS)
    headers = {'User-Agent': user_agent}
    proxy_url = PROXY if PROXY else None

    try:
        if method.lower() == 'post' and POST_METHOD == 'post':
            if VERBOSE_REQUESTS == 'vv':
                print(f"[*] POST_url: {post_url} | post_data: {post_data}")
            async with session.post(post_url, params=post_data, headers=headers, proxy=proxy_url,
                                    ssl=False) as response:
                text = await response.text(errors="ignore")
                return response.status, text, post_url, form, post_data

        if VERBOSE_REQUESTS == 'vv':
            print(f"[*] GET_url: {post_url} | GET_data: {post_data}")
        async with session.get(post_url, params=post_data, headers=headers, proxy=proxy_url, ssl=False) as response:
            text = await response.text(errors="ignore")
            return response.status, text, post_url, form, post_data

    except aiohttp.ClientError as e:
        print(f"An HTTP error occurred in submit_form: {e}")
        return None, None, post_url, form, post_data

    except Exception as e:
        print(f"An unexpected error occurred in submit_form: {e}")
        return None, None, post_url, form, post_data


def _extract_forms(html: str):
    parsed_html = BeautifulSoup(html, features='lxml')
    return parsed_html.findAll("form")


async def analyze_response(status, text, url, form, payload, answers):
    output_folder = OUTPUT
    os.makedirs(output_folder, exist_ok=True)

    if answers.search(text):
        print(f'\n{C.bold_green}[+] URL: {url} | Status: {status}{C.norm}\n'
              f'{C.blue}{form}{C.norm}\n'
              f'{C.bold_cyan}{payload}{C.norm}\n')

        output_file = f'{output_folder}/vulnerable_forms.txt'
        await writing_to_file_of_successful_payload(status, url, form, payload, output_file)

    elif status == 403 and VERBOSE == 'v':
        print(f'{C.norm}[-] URL: {url} | Status: {C.bold_red}{status} | Payload: {payload}{C.norm}')

        output_file = f'{output_folder}/403_forms.txt'
        await write_to_file(f'URL: {url} | Status: {status} | Payload: {payload}', output_file)

    elif status == 429 and VERBOSE == 'v':
        print(f'{C.red}[-] Too many requests, URL: {url} | Status: {C.bold_red}{status} {C.norm}')

        output_file = f'{output_folder}/429_forms.txt'
        await write_to_file(f'URL: {url} | Status: {status}', output_file)

    elif status != 200 and VERBOSE == 'v':
        print(f'{C.bold_red}[-] URL: {url} | Status: {status} {C.norm}')

    elif VERBOSE == 'v':
        print(f'{C.norm}[-] URL: {url} | Status: {status} {C.norm}')


async def process_forms(forms, form_queue: asyncio.Queue, url):
    for form in forms:
        await form_queue.put((url, form))


async def process_link(link, form_queue: asyncio.Queue, session):
    url, response_status, html = await make_request(link, session)

    if html is None:
        print(f'{C.yellow}[!] Skipping URL due to missing data: {url}{C.norm}')
        return

    loop = asyncio.get_running_loop()
    try:
        with ThreadPoolExecutor() as pool:
            extracted_forms = await loop.run_in_executor(
                pool, _extract_forms, html
            )
            await process_forms(extracted_forms, form_queue, url)

    except Exception as e:
        print(f'Error in ThreadPoolExecutor: {e}')


async def get_form_page(link_queue: Queue, form_queue: Queue, session):
    while True:
        link = await link_queue.get()

        try:
            await process_link(link, form_queue, session)
        except Exception as e:
            print(f'{C.red}[!] Error in get_form_page: {e}{C.norm}')
        finally:
            link_queue.task_done()


async def generate_payload_forms(forms, payloads):
    forms_with_payload = []
    scheme = forms[0].replace('https://', 'http://')

    for payload in payloads:
        action = forms[1].get("action")
        post_url = urlparse.urljoin(scheme, action)
        method = forms[1].get("method")

        inputs_list = forms[1].findAll("input")

        post_data = {}
        for input in inputs_list:
            input_name = input.get("name")
            input_type = input.get("type")
            input_value = input.get("value")

            if input_type in {"text", "TEXT", None}:
                input_value = payload

            if input_name:
                post_data[input_name] = input_value

        post_data = {k: v for k, v in post_data.items() if v is not None}

        forms_with_payload.append((method, post_url, forms[1], post_data))
    return forms_with_payload


async def process_form(forms, payloads, answers, session):
    forms_with_payload = await generate_payload_forms(forms, payloads)

    tasks = [
        submit_form(method=form[0], post_url=form[1], form=form[2], post_data=form[3], session=session)
        for form in forms_with_payload
        if form[0] is not None
    ]

    if tasks:
        for as_completed in asyncio.as_completed(tasks):
            status, text, url, form, payload = await as_completed

            await analyze_response(status=status, text=text, url=url, form=form, payload=payload, answers=answers)


async def command_injection(form_queue: Queue, payloads, answers, session):
    while True:
        forms = await form_queue.get()

        try:
            await process_form(forms, payloads, answers, session)
        except Exception as e:
            print(f'{C.red}[!] Error in command_injection: {e}{C.norm}')
        finally:
            form_queue.task_done()


async def cancel_tasks(tasks):
    for task in tasks:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

@timer_decorator
async def main():
    link_queue = asyncio.Queue(maxsize=100)
    form_queue = asyncio.Queue(maxsize=50)

    payload_patterns = await read_file_to_list(PAYLOADS)
    answer_patterns = await load_patterns(ANSWERS)

    producer = asyncio.create_task(read_file_to_queue(INPUT, link_queue))

    timeout_for_all_requests = aiohttp.ClientTimeout(total=TIMEOUT)
    async with aiohttp.ClientSession(timeout=timeout_for_all_requests) as session:
        form_getters = [
            asyncio.create_task(
                get_form_page(link_queue=link_queue,
                              form_queue=form_queue,
                              session=session)
            ) for _ in range(20)
        ]

        command_getters = [
            asyncio.create_task(
                command_injection(form_queue=form_queue,
                                  payloads=payload_patterns,
                                  answers=answer_patterns,
                                  session=session)
            ) for _ in range(20)
        ]

        await asyncio.gather(producer, return_exceptions=True)

        await link_queue.join()
        await cancel_tasks(form_getters)

        await form_queue.join()
        await cancel_tasks(form_getters)



if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"{C.red} [!] Program interrupted by user. Exiting...{C.norm}")
    except Exception as e:
        print(f"{C.red}[!] Unexpected error: {e}{C.norm}")
