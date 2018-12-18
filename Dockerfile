FROM python:3.7
ADD server/main.py /
ADD server/search.py /
ADD requirements.txt /
RUN pip install -r ./requirements.txt
CMD [ "python", "./main.py" ]
