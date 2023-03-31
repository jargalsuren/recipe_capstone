#Specifying how to build a Docker image
FROM continuumio/anaconda3:2022.10
#copying the current directory to the /code directory in the container
ADD . /code
#setting the working directory to /code
WORKDIR /code
#installing the requirements
RUN pip install -r requirements.txt
#exposing the port 5000
EXPOSE 5000
#running the app.py file
CMD ["python", "app.py"]


