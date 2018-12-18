FROM python:3.7g
ADD server/main.py /
ADD requirements.txt /
RUN pip install -r ./requirements.txt
CMD [ "python", "./main.py" ]
