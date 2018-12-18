FROM python:3
ADD server/main.py /
RUN pip install -r requirements.txt
CMD [ "python", "./main.py" ]
